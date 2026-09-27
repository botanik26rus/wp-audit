#!/usr/bin/env bash
#
# wp-security-audit.sh
# Read-only WordPress compromise / integrity audit.
# It does NOT delete, quarantine, chmod, update, or rewrite site files.
#
# Usage:
#   chmod +x wp-security-audit.sh
#   sudo ./wp-security-audit.sh
#
# Optional:
#   sudo ./wp-security-audit.sh /path/to/wordpress
#   sudo ./wp-security-audit.sh --deep /path/to/wordpress
#
# Exit codes:
#   0 - no high-confidence critical finding
#   1 - critical/high-confidence findings detected
#   2 - usage/environment error

set -uo pipefail
IFS=$'\n\t'

AUDIT_VERSION="1.0.1"
DEEP=0
WP_ROOT=""

for arg in "$@"; do
    case "$arg" in
        --deep) DEEP=1 ;;
        -h|--help)
            cat <<'EOF'
wp-security-audit.sh [--deep] [WORDPRESS_ROOT]

Read-only WordPress security audit.
--deep  additionally scans PHP source for several high-risk code patterns.
EOF
            exit 0
            ;;
        --*) echo "Unknown option: $arg" >&2; exit 2 ;;
        *) WP_ROOT="$arg" ;;
    esac
done

WP_ROOT="${WP_ROOT:-$(pwd -P)}"
WP_ROOT="$(readlink -f "$WP_ROOT" 2>/dev/null || printf '%s' "$WP_ROOT")"
SCRIPT_REAL="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
SCRIPT_REL=""
if [[ "$SCRIPT_REAL" == "$WP_ROOT/"* ]]; then
    SCRIPT_REL="${SCRIPT_REAL#"$WP_ROOT/"}"
fi

if [[ ! -d "$WP_ROOT/wp-includes" || ! -f "$WP_ROOT/wp-includes/version.php" ]]; then
    echo "ERROR: $WP_ROOT does not look like a WordPress root." >&2
    echo "Run this script from the WordPress directory or pass the path as an argument." >&2
    exit 2
fi

SITE_OWNER="$(stat -c '%U' "$WP_ROOT" 2>/dev/null || echo unknown)"
SITE_GROUP="$(stat -c '%G' "$WP_ROOT" 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"

if [[ $EUID -eq 0 ]]; then
    REPORT_DIR="/root"
else
    REPORT_DIR="${HOME:-/tmp}"
fi
REPORT="$REPORT_DIR/wp-security-audit-$STAMP.log"
RECOMMEND="$REPORT_DIR/wp-security-audit-$STAMP.commands.txt"
TMPDIR_AUDIT="$(mktemp -d "${TMPDIR:-/tmp}/wp-audit.XXXXXX")"
trap 'rm -rf "$TMPDIR_AUDIT"' EXIT

CRITICAL=0
WARNINGS=0
NOTES=0

touch "$REPORT" "$RECOMMEND" 2>/dev/null || {
    echo "ERROR: Cannot create report in $REPORT_DIR" >&2
    exit 2
}
chmod 600 "$REPORT" "$RECOMMEND" 2>/dev/null || true

exec > >(tee -a "$REPORT") 2>&1

section() {
    printf '\n============================================================\n'
    printf '%s\n' "$1"
    printf '============================================================\n'
}

ok()   { printf '[ OK ] %s\n' "$*"; }
note() { NOTES=$((NOTES+1)); printf '[INFO] %s\n' "$*"; }
warn() { WARNINGS=$((WARNINGS+1)); printf '[WARN] %s\n' "$*"; }
crit() { CRITICAL=$((CRITICAL+1)); printf '[CRIT] %s\n' "$*"; }

add_cmd() {
    printf '%s\n' "$*" >> "$RECOMMEND"
}

quote() { printf '%q' "$1"; }

run_site() {
    # Never execute WordPress/WP-CLI as root when the webroot belongs to another user.
    if [[ $EUID -eq 0 && "$SITE_OWNER" != "root" && "$SITE_OWNER" != "unknown" ]] && command -v sudo >/dev/null 2>&1; then
        sudo -u "$SITE_OWNER" -H "$@"
    else
        "$@"
    fi
}

VERSION="$(
    sed -n "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" \
        "$WP_ROOT/wp-includes/version.php" 2>/dev/null | head -1
)"
[[ -n "$VERSION" ]] || VERSION="unknown"

section "WORDPRESS SECURITY AUDIT"
echo "Audit version : $AUDIT_VERSION"
echo "Time          : $(date -Is)"
echo "Host          : $HOST"
echo "WordPress root: $WP_ROOT"
echo "Site owner    : $SITE_OWNER:$SITE_GROUP"
echo "WordPress     : $VERSION"
echo "Report        : $REPORT"
echo "Commands      : $RECOMMEND"
echo "Mode          : $([[ $DEEP -eq 1 ]] && echo deep || echo normal)"
echo
echo "This audit is read-only. It does not delete or repair files."
if [[ -n "$SCRIPT_REL" ]]; then
    note "The audit script is inside the WordPress tree ($SCRIPT_REL). It is excluded from the core checksum check. After use, move it outside the web root (for example /root/bin/)."
fi

section "1. BASIC FILE OWNERSHIP AND PERMISSIONS"

ROOT_MODE="$(stat -c '%a' "$WP_ROOT" 2>/dev/null || echo '?')"
echo "Webroot mode: $ROOT_MODE"

BAD_OWNER_FILE="$TMPDIR_AUDIT/bad-owner.txt"
if [[ "$SITE_OWNER" != "unknown" ]]; then
    find "$WP_ROOT" -xdev \( ! -user "$SITE_OWNER" -o ! -group "$SITE_GROUP" \) \
        -printf '%u:%g %m %p\n' 2>/dev/null | head -200 > "$BAD_OWNER_FILE" || true
    if [[ -s "$BAD_OWNER_FILE" ]]; then
        warn "Files/directories with ownership different from $SITE_OWNER:$SITE_GROUP were found (first 200 shown):"
        cat "$BAD_OWNER_FILE"
        add_cmd "# Normalize WordPress ownership:"
        add_cmd "chown -R $(quote "$SITE_OWNER:$SITE_GROUP") $(quote "$WP_ROOT")"
    else
        ok "Ownership is consistent with $SITE_OWNER:$SITE_GROUP."
    fi
fi

WORLD_WRITABLE="$TMPDIR_AUDIT/world-writable.txt"
find "$WP_ROOT" -xdev \( -type f -o -type d \) -perm -0002 \
    -printf '%m %u:%g %p\n' 2>/dev/null > "$WORLD_WRITABLE" || true
if [[ -s "$WORLD_WRITABLE" ]]; then
    crit "World-writable files/directories found:"
    cat "$WORLD_WRITABLE"
    add_cmd "# Standard WordPress permissions (review before applying if you intentionally use ACLs/custom modes):"
    add_cmd "find $(quote "$WP_ROOT") -type d -exec chmod 755 {} \\;"
    add_cmd "find $(quote "$WP_ROOT") -type f -exec chmod 644 {} \\;"
    add_cmd "chmod 640 $(quote "$WP_ROOT/wp-config.php")"
else
    ok "No world-writable files/directories."
fi

if [[ -f "$WP_ROOT/wp-config.php" ]]; then
    MODE="$(stat -c '%a' "$WP_ROOT/wp-config.php" 2>/dev/null || echo '?')"
    echo "wp-config.php mode: $MODE"
    if [[ "$MODE" =~ ^[0-7]{3,4}$ ]]; then
        OCT=$((8#$MODE))
        if (( OCT & 0022 )); then
            crit "wp-config.php is writable by group and/or others."
            add_cmd "chmod 640 $(quote "$WP_ROOT/wp-config.php")"
        else
            ok "wp-config.php is not writable by group/others."
        fi
    fi
fi

section "2. PHP IN UPLOADS / HIDDEN PHP / WP-CONTENT ROOT"

UPLOAD_PHP="$TMPDIR_AUDIT/upload-php.txt"
if [[ -d "$WP_ROOT/wp-content/uploads" ]]; then
    find "$WP_ROOT/wp-content/uploads" -type f \
        \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \
           -o -iname '*.php[0-9]' -o -iname '*.php[0-9][0-9]' \) \
        -print 2>/dev/null > "$UPLOAD_PHP" || true
    if [[ -s "$UPLOAD_PHP" ]]; then
        crit "Executable PHP-like files found under wp-content/uploads:"
        cat "$UPLOAD_PHP"
        add_cmd "# Quarantine these after reviewing the report; do NOT blindly rm them:"
        while IFS= read -r f; do
            rel="${f#"$WP_ROOT"/}"
            add_cmd "mkdir -p /root/wp-quarantine-$STAMP/$(quote "$(dirname "$rel")") && mv -- $(quote "$f") /root/wp-quarantine-$STAMP/$(quote "$rel")"
        done < "$UPLOAD_PHP"
    else
        ok "No PHP-like files under uploads."
    fi

    UP_HT="$WP_ROOT/wp-content/uploads/.htaccess"
    if [[ -f "$UP_HT" ]] && grep -Eqi 'FilesMatch|php|Require[[:space:]]+all[[:space:]]+denied|Deny[[:space:]]+from[[:space:]]+all' "$UP_HT"; then
        ok "uploads/.htaccess contains a PHP/access restriction."
    else
        warn "No obvious PHP execution restriction found in uploads/.htaccess."
        add_cmd "# Apache: block PHP execution in uploads:"
        add_cmd "cat > $(quote "$WP_ROOT/wp-content/uploads/.htaccess") <<'EOF'"
        add_cmd '<FilesMatch "\.(php|phtml|phar|php[0-9]*)$">'
        add_cmd '    Require all denied'
        add_cmd '</FilesMatch>'
        add_cmd 'EOF'
        add_cmd "chown $(quote "$SITE_OWNER:$SITE_GROUP") $(quote "$WP_ROOT/wp-content/uploads/.htaccess")"
        add_cmd "chmod 644 $(quote "$WP_ROOT/wp-content/uploads/.htaccess")"
    fi
fi

HIDDEN_PHP="$TMPDIR_AUDIT/hidden-php.txt"
find "$WP_ROOT/wp-content" -type f -name '.*.php' -print 2>/dev/null > "$HIDDEN_PHP" || true
if [[ -s "$HIDDEN_PHP" ]]; then
    crit "Hidden PHP files found in wp-content:"
    cat "$HIDDEN_PHP"
else
    ok "No hidden .*.php files under wp-content."
fi

CONTENT_ROOT_PHP="$TMPDIR_AUDIT/content-root-php.txt"
find "$WP_ROOT/wp-content" -maxdepth 1 -type f -name '*.php' \
    -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null > "$CONTENT_ROOT_PHP" || true
if [[ -s "$CONTENT_ROOT_PHP" ]]; then
    echo "PHP files directly in wp-content (review drop-ins/custom files):"
    cat "$CONTENT_ROOT_PHP"
else
    ok "No PHP files directly in wp-content."
fi

section "3. KNOWN WEB-SHELL NAMES AND MARKERS"

KNOWN="$TMPDIR_AUDIT/known.txt"
find "$WP_ROOT" -type f \
    \( -iname 'v80.php' -o -iname 'v90.php' -o -iname 'v911.php' \
       -o -iname 'l.php' -o -iname 'wp-l0gin.php' -o -iname 'wp-log1n.php' \
       -o -iname 'lock360.php' -o -iname 'buy.php' -o -iname 'goods.php' \
       -o -iname 'mah.php' -o -iname 'click.php' -o -iname 'getdomains.php' \) \
    -print 2>/dev/null > "$KNOWN" || true
if [[ -s "$KNOWN" ]]; then
    crit "Known/suspicious filenames found:"
    cat "$KNOWN"
else
    ok "Known filenames from common/observed web-shell campaigns were not found."
fi

MARKERS="$TMPDIR_AUDIT/markers.txt"
grep -RIl --binary-files=without-match \
    -E 'loknya|current_dir[^[:cntrl:]]*Writeable|document_root[^[:cntrl:]]*Writeable' \
    "$WP_ROOT" 2>/dev/null | grep -vFx "$SCRIPT_REAL" | head -100 > "$MARKERS" || true
if [[ -s "$MARKERS" ]]; then
    crit "Web-shell markers found:"
    cat "$MARKERS"
else
    ok "No 'loknya'/Writeable web-shell markers found."
fi

section "4. PHP CONFIG OVERRIDES / AUTO-PREPEND"

CFGFILES="$TMPDIR_AUDIT/php-config-files.txt"
find "$WP_ROOT" -maxdepth 4 -type f \
    \( -name '.user.ini' -o -name 'php.ini' -o -name '.htaccess' \) \
    -print 2>/dev/null > "$CFGFILES" || true
cat "$CFGFILES" 2>/dev/null || true

AUTOPREP="$TMPDIR_AUDIT/autoprep.txt"
if [[ -s "$CFGFILES" ]]; then
    xargs -r grep -HnEi \
        'auto_prepend_file|auto_append_file|php_value[[:space:]]+auto_prepend|php_value[[:space:]]+auto_append' \
        < "$CFGFILES" 2>/dev/null > "$AUTOPREP" || true
fi
if [[ -s "$AUTOPREP" ]]; then
    crit "auto_prepend/auto_append configuration found:"
    cat "$AUTOPREP"
else
    ok "No auto_prepend/auto_append directives found in local PHP/Apache config files."
fi

if [[ -f "$WP_ROOT/wp-config.php" ]]; then
    CFG_SUSP="$TMPDIR_AUDIT/wpconfig-suspicious.txt"
    grep -nEi \
        'auto_prepend|auto_append|base64_decode|gzinflate|eval[[:space:]]*\(|assert[[:space:]]*\(|shell_exec|passthru|proc_open|popen|system[[:space:]]*\(' \
        "$WP_ROOT/wp-config.php" > "$CFG_SUSP" 2>/dev/null || true
    if [[ -s "$CFG_SUSP" ]]; then
        crit "Suspicious execution/obfuscation pattern in wp-config.php:"
        cat "$CFG_SUSP"
    else
        ok "No obvious execution/obfuscation pattern in wp-config.php."
    fi
fi

section "5. WORDPRESS CORE INTEGRITY"

if command -v wp >/dev/null 2>&1; then
    CORE_OUT="$TMPDIR_AUDIT/core-check.txt"
    CORE_ARGS=(core verify-checksums --path="$WP_ROOT" --version="$VERSION" --include-root)
    if [[ -n "$SCRIPT_REL" ]]; then
        CORE_ARGS+=(--exclude="$SCRIPT_REL")
    fi
    run_site wp "${CORE_ARGS[@]}" >"$CORE_OUT" 2>&1
    CORE_RC=$?
    cat "$CORE_OUT"

    CORE_CHANGED=0
    CORE_EXTRA=0
    grep -qE 'File doesn.t verify against checksum|File is missing|doesn.t verify against checksums|Error:' "$CORE_OUT" && CORE_CHANGED=1 || true
    grep -qE 'File should not exist:' "$CORE_OUT" && CORE_EXTRA=1 || true

    if [[ $CORE_CHANGED -eq 1 ]]; then
        crit "WordPress core files failed integrity verification."
        add_cmd "# Repair core safely: download the SAME version to a temporary directory, then replace wp-admin/wp-includes and root core PHP files."
        add_cmd "WP=$(quote "$WP_ROOT"); VER=$(quote "$VERSION"); OWNER=$(quote "$SITE_OWNER"); TMP=\$(mktemp -d)"
        if [[ $EUID -eq 0 && "$SITE_OWNER" != "root" && "$SITE_OWNER" != "unknown" ]]; then
            add_cmd "sudo -u $(quote "$SITE_OWNER") -H wp core download --version=\"\$VER\" --skip-content --path=\"\$TMP\""
        else
            add_cmd "wp core download --version=\"\$VER\" --skip-content --path=\"\$TMP\""
        fi
        add_cmd "rsync -a --delete \"\$TMP/wp-admin/\" \"\$WP/wp-admin/\""
        add_cmd "rsync -a --delete \"\$TMP/wp-includes/\" \"\$WP/wp-includes/\""
        add_cmd "for f in \"\$TMP\"/*.php; do b=\$(basename \"\$f\"); [[ \"\$b\" == wp-config-sample.php ]] && continue; install -o $(quote "$SITE_OWNER") -g $(quote "$SITE_GROUP") -m 0644 \"\$f\" \"\$WP/\$b\"; done"
        add_cmd "# Re-run this audit. Extra root files reported by checksum should be reviewed/quarantined separately."
    elif [[ $CORE_EXTRA -eq 1 ]]; then
        warn "Core files verify, but extra files exist in WordPress core/root locations. Review every "File should not exist" entry."
        add_cmd "# Review/quarantine only the extra files reported above; legitimate files such as robots.txt may exist."
    elif [[ $CORE_RC -ne 0 ]]; then
        warn "Core checksum command returned a non-zero status without a recognized file-integrity pattern; review its output."
    else
        ok "WordPress core verifies against official checksums."
    fi
else
    warn "WP-CLI is not installed; core/plugin/update/database checks are limited."
    add_cmd "# Install WP-CLI from the official signed PHAR, then re-run the audit."
fi

section "6. PLUGIN INTEGRITY"

if command -v wp >/dev/null 2>&1; then
    PLUGIN_OUT="$TMPDIR_AUDIT/plugin-check.txt"
    run_site wp plugin verify-checksums \
        --all --strict \
        --path="$WP_ROOT" \
        --skip-plugins --skip-themes >"$PLUGIN_OUT" 2>&1
    PLUGIN_RC=$?
    cat "$PLUGIN_OUT"

    BAD_PLUGINS="$TMPDIR_AUDIT/bad-plugins.txt"
    awk '
      /File was added|File was removed|doesn.t verify against checksum|File is missing/ {
        if ($1 != "plugin_name" && $1 !~ /^Warning:/ && $1 !~ /^Error:/) print $1
      }
    ' "$PLUGIN_OUT" | sort -u > "$BAD_PLUGINS"

    SKIPPED_PLUGINS="$TMPDIR_AUDIT/skipped-plugins.txt"
    sed -nE 's/.*version [^ ]+ of plugin ([^, ]+), skipping.*/\1/p' "$PLUGIN_OUT" \
        | sort -u > "$SKIPPED_PLUGINS"

    if [[ -s "$BAD_PLUGINS" ]]; then
        crit "One or more plugins failed checksum verification."
        if [[ -s "$BAD_PLUGINS" ]]; then
            echo "Plugins with changed/added/missing files:"
            cat "$BAD_PLUGINS"
            while IFS= read -r p; do
                [[ -n "$p" ]] || continue
                PVER="$(run_site wp plugin get "$p" --field=version --path="$WP_ROOT" --skip-plugins --skip-themes 2>/dev/null || true)"
                if [[ -n "$PVER" ]]; then
                    add_cmd "# Reinstall verified WordPress.org plugin $p ($PVER):"
                    if [[ $EUID -eq 0 && "$SITE_OWNER" != "root" && "$SITE_OWNER" != "unknown" ]]; then
                        add_cmd "sudo -u $(quote "$SITE_OWNER") -H wp plugin install $(quote "$p") --version=$(quote "$PVER") --force --path=$(quote "$WP_ROOT") --skip-plugins --skip-themes"
                    else
                        add_cmd "wp plugin install $(quote "$p") --version=$(quote "$PVER") --force --path=$(quote "$WP_ROOT") --skip-plugins --skip-themes"
                    fi
                fi
            done < "$BAD_PLUGINS"
        fi
    elif [[ $PLUGIN_RC -ne 0 ]]; then
        warn "Plugin checksum command returned non-zero, but no changed/added/missing plugin files were parsed. This commonly happens when checksums are unavailable; review warnings above."
    else
        ok "All verifiable plugins passed checksums."
    fi

    if [[ -s "$SKIPPED_PLUGINS" ]]; then
        warn "These plugins have no WordPress.org checksum and cannot be trusted by checksum alone:"
        cat "$SKIPPED_PLUGINS"
        while IFS= read -r p; do
            [[ -n "$p" ]] || continue
            add_cmd "# $p: reinstall the same/current version from its OFFICIAL vendor/source, then re-run the audit."
        done < "$SKIPPED_PLUGINS"
    fi
fi

section "7. THEMES / PLUGINS / UPDATES"

if command -v wp >/dev/null 2>&1; then
    echo "--- Plugins ---"
    run_site wp plugin list \
        --fields=name,status,version,update \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || warn "Could not list plugins."

    echo
    echo "--- Themes ---"
    run_site wp theme list \
        --fields=name,status,version,update \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || warn "Could not list themes."

    echo
    echo "--- Core update check ---"
    CORE_UPDATE="$TMPDIR_AUDIT/core-update.txt"
    run_site wp core check-update --format=json \
        --path="$WP_ROOT" --skip-plugins --skip-themes >"$CORE_UPDATE" 2>&1 || true
    cat "$CORE_UPDATE"
    if grep -q '"version"' "$CORE_UPDATE"; then
        warn "A WordPress core update may be available. Security releases should be applied promptly."
        if [[ $EUID -eq 0 && "$SITE_OWNER" != "root" && "$SITE_OWNER" != "unknown" ]]; then
            add_cmd "# After taking a backup, update WordPress core:"
            add_cmd "sudo -u $(quote "$SITE_OWNER") -H wp core update --path=$(quote "$WP_ROOT") --skip-plugins --skip-themes"
        else
            add_cmd "# After taking a backup, update WordPress core:"
            add_cmd "wp core update --path=$(quote "$WP_ROOT") --skip-plugins --skip-themes"
        fi
    fi

    echo
    echo "--- Plugin updates available ---"
    run_site wp plugin list --update=available \
        --fields=name,status,version,update_version \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || true

    echo
    echo "--- Theme updates available ---"
    run_site wp theme list --update=available \
        --fields=name,status,version,update_version \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || true
fi

section "8. MU-PLUGINS, DROP-INS, SYMLINKS"

if [[ -d "$WP_ROOT/wp-content/mu-plugins" ]]; then
    MU="$TMPDIR_AUDIT/mu.txt"
    find "$WP_ROOT/wp-content/mu-plugins" -type f \
        -printf '%m %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null > "$MU" || true
    if [[ -s "$MU" ]]; then
        warn "MU-plugin files exist. WP-CLI --skip-plugins does NOT skip MU-plugins; review these carefully:"
        cat "$MU"
    else
        ok "mu-plugins directory is empty."
    fi
else
    ok "No mu-plugins directory."
fi

for d in advanced-cache.php object-cache.php db.php sunrise.php maintenance.php; do
    if [[ -f "$WP_ROOT/wp-content/$d" ]]; then
        warn "WordPress drop-in present: wp-content/$d (may be legitimate; review origin)."
        stat -c '%a %U:%G %y %n' "$WP_ROOT/wp-content/$d" 2>/dev/null || true
    fi
done

SYMS="$TMPDIR_AUDIT/symlinks.txt"
find "$WP_ROOT" -xdev -type l -printf '%p -> %l\n' 2>/dev/null > "$SYMS" || true
if [[ -s "$SYMS" ]]; then
    warn "Symbolic links exist in WordPress tree; review them:"
    cat "$SYMS"
else
    ok "No symbolic links in WordPress tree."
fi

section "9. RECENT FILE CHANGES (ctime, LAST 14 DAYS)"

RECENT="$TMPDIR_AUDIT/recent.txt"
find "$WP_ROOT" -xdev -type f -ctime -14 \
    -printf '%C@ %CY-%Cm-%Cd %CH:%CM:%CS %u:%g %m %p\n' 2>/dev/null \
    | sort -nr | head -150 | cut -d' ' -f2- > "$RECENT" || true
if [[ -s "$RECENT" ]]; then
    echo "Newest 150 files by ctime:"
    cat "$RECENT"
    note "ctime is shown because file owners can forge mtime with touch, while changing ctime normally requires changing filesystem metadata."
else
    ok "No files with ctime in the last 14 days."
fi

section "10. WORDPRESS ADMINISTRATORS AND CRON"

# Runtime WP-CLI commands are always executed as the site owner, never as root.
# MU-plugins may still load; this is explicitly surfaced in section 8.
if command -v wp >/dev/null 2>&1; then
    echo "--- Administrators ---"
    run_site wp user list \
        --role=administrator \
        --fields=ID,user_login,user_email,user_registered \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || warn "Could not list administrators."

    echo
    echo "--- WordPress cron events ---"
    run_site wp cron event list \
        --fields=hook,next_run_gmt,next_run_relative,recurrence \
        --format=table --path="$WP_ROOT" \
        --skip-plugins --skip-themes 2>&1 || warn "Could not list WordPress cron events."

    echo
    echo "--- siteurl / home ---"
    printf 'siteurl: '
    run_site wp option get siteurl --path="$WP_ROOT" --skip-plugins --skip-themes 2>&1 || true
    printf 'home   : '
    run_site wp option get home --path="$WP_ROOT" --skip-plugins --skip-themes 2>&1 || true
fi

section "11. OS ACCOUNT PERSISTENCE CHECKS"

if [[ "$SITE_OWNER" != "unknown" ]]; then
    id "$SITE_OWNER" 2>/dev/null || true

    if [[ $EUID -eq 0 ]]; then
        echo
        echo "--- sudo rights for $SITE_OWNER ---"
        SUDO_OUT="$TMPDIR_AUDIT/sudo.txt"
        sudo -u "$SITE_OWNER" -H sudo -n -l >"$SUDO_OUT" 2>&1 || true
        cat "$SUDO_OUT"
        if grep -Eq '\(ALL(:ALL)?\)|NOPASSWD' "$SUDO_OUT"; then
            crit "Site account appears to have sudo privileges. This is unusual for a hosting account; verify deliberately."
        fi

        echo
        echo "--- crontab for $SITE_OWNER ---"
        crontab -u "$SITE_OWNER" -l 2>&1 || true
    else
        note "Run as root to inspect the hosting user's crontab and sudo rights."
    fi

    HOME_DIR="$(getent passwd "$SITE_OWNER" 2>/dev/null | cut -d: -f6)"
    if [[ -n "$HOME_DIR" && -d "$HOME_DIR" ]]; then
        echo
        echo "--- SSH authorized_keys under $HOME_DIR ---"
        find "$HOME_DIR" -type f \
            \( -name authorized_keys -o -name authorized_keys2 \) \
            -print -exec sed -n '1,80p' {} \; 2>/dev/null || true
    fi
fi

section "12. DEEP STATIC PHP SCAN"

if [[ $DEEP -eq 1 ]]; then
    DEEP_OUT="$TMPDIR_AUDIT/deep.txt"
    grep -RInE --include='*.php' --binary-files=without-match \
        'eval[[:space:]]*\([[:space:]]*base64_decode|gzinflate[[:space:]]*\([[:space:]]*base64_decode|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|preg_replace[[:space:]]*\([^;]*/e[^;]*\$_(GET|POST|REQUEST|COOKIE)|\$_(GET|POST|REQUEST|COOKIE)[^;]{0,200}(shell_exec|passthru|proc_open|popen|system)[[:space:]]*\(' \
        "$WP_ROOT" 2>/dev/null | head -300 > "$DEEP_OUT" || true
    if [[ -s "$DEEP_OUT" ]]; then
        crit "High-risk code patterns found (manual review required; false positives are possible):"
        cat "$DEEP_OUT"
    else
        ok "No selected high-risk PHP code patterns found."
    fi
else
    note "Deep static scan skipped. Re-run with: sudo $(quote "$0") --deep $(quote "$WP_ROOT")"
fi

section "13. OPTIONAL EXTERNAL SCANNERS"

if command -v wordfence >/dev/null 2>&1; then
    echo "Wordfence CLI detected: $(command -v wordfence)"
    echo "Useful second-opinion commands:"
    echo "  wordfence malware-scan $(quote "$WP_ROOT")"
    echo "  wordfence vuln-scan $(quote "$WP_ROOT")"
else
    note "Wordfence CLI is not installed. It can provide a second-opinion malware/vulnerability scan, but check its current licensing/support status before relying on it."
fi

if command -v clamscan >/dev/null 2>&1; then
    echo "ClamAV detected: $(command -v clamscan)"
    echo "Optional command: clamscan -ri $(quote "$WP_ROOT")"
fi

section "14. SUMMARY"

echo "Critical/high-confidence findings : $CRITICAL"
echo "Warnings                         : $WARNINGS"
echo "Informational notes              : $NOTES"
echo
echo "Full report:"
echo "  $REPORT"
echo
echo "Suggested remediation commands:"
echo "  $RECOMMEND"

if [[ -s "$RECOMMEND" ]]; then
    echo
    echo "----- COMMANDS (REVIEW BEFORE RUNNING) -----"
    cat "$RECOMMEND"
else
    echo
    echo "No remediation commands were generated."
fi

echo
echo "IMPORTANT:"
echo "- A clean checksum does not prove the database, premium/custom code, server account, or another site is clean."
echo "- Do not blindly execute quarantine/reinstall commands without reviewing the matching finding."
echo "- After incident cleanup, rotate WordPress administrator passwords, DB password, salts, hosting-panel credentials, and any exposed secrets."
echo "- Keep WordPress core, plugins, and themes on supported security-patched versions."

if (( CRITICAL > 0 )); then
    exit 1
fi
exit 0
