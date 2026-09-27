# WordPress Security Audit

`wp-audit.sh` — read-only Bash-скрипт для первичного аудита безопасности WordPress после подозрения на компрометацию, заражение или изменение файлов.

Скрипт **не удаляет, не помещает в карантин, не меняет права, не обновляет и не переписывает файлы сайта автоматически**. Он собирает отчёт, отмечает критические находки и предупреждения, а потенциальные команды исправления записывает отдельно для последующей ручной проверки.

## Что проверяет

Скрипт выполняет комплексную проверку WordPress и окружения, в том числе:

- владельцев и права файлов и каталогов;
- world-writable файлы и каталоги;
- права на `wp-config.php`;
- PHP/PHTML/PHAR-файлы внутри `wp-content/uploads`;
- скрытые PHP-файлы в `wp-content`;
- PHP-файлы непосредственно в корне `wp-content`;
- известные подозрительные имена web-shell файлов;
- характерные маркеры web-shell;
- `.user.ini`, `php.ini`, `.htaccess`;
- `auto_prepend_file` и `auto_append_file`;
- подозрительные конструкции в `wp-config.php`;
- целостность файлов ядра WordPress через WP-CLI;
- контрольные суммы плагинов WordPress.org;
- доступные обновления ядра, плагинов и тем;
- MU-плагины и WordPress drop-ins;
- символические ссылки;
- недавно изменённые файлы по `ctime`;
- пользователей WordPress с ролью администратора;
- WordPress Cron;
- `siteurl` и `home`;
- права системного пользователя сайта;
- его `crontab`;
- SSH `authorized_keys`;
- в режиме `--deep` — ряд опасных PHP-конструкций и способов выполнения команд;
- наличие Wordfence CLI и ClamAV как дополнительных средств проверки.

## Требования

Основное окружение:

- Linux;
- Bash;
- стандартные GNU-утилиты: `find`, `grep`, `sed`, `awk`, `xargs`, `stat`, `readlink`, `sort`, `head`, `cut`;
- рекомендуется запуск от `root`.

Для расширенной проверки WordPress желательно установить:

- [WP-CLI](https://wp-cli.org/)

Опционально:

- Wordfence CLI;
- ClamAV.

Без WP-CLI скрипт всё равно выполнит файловые проверки, но проверка контрольных сумм ядра и плагинов, списка пользователей, WordPress Cron и некоторых других данных будет ограничена.

## Установка

### Вариант 1. Скачать с GitHub через `curl`

```bash
curl -fsSL \
  https://raw.githubusercontent.com/botanik26rus/wp-audit/main/wp-audit.sh \
  -o /usr/local/sbin/wp-audit
```

Сделать файл исполняемым:

```bash
chmod 755 /usr/local/sbin/wp-audit
```

После этого скрипт можно запускать как обычную команду:

```bash
sudo wp-audit /path/to/wordpress
```

### Вариант 2. Скачать через `wget`

```bash
wget -O /usr/local/sbin/wp-audit \
  https://raw.githubusercontent.com/botanik26rus/wp-audit/main/wp-audit.sh
```

```bash
chmod 755 /usr/local/sbin/wp-audit
```

### Вариант 3. Клонировать репозиторий

```bash
git clone https://github.com/botanik26rus/wp-audit.git
cd REPOSITORY
chmod +x wp-audit.sh
```

Запуск:

```bash
sudo ./wp-audit.sh /path/to/wordpress
```

## Использование

Можно запустить скрипт из корня WordPress:

```bash
cd /home/example/web/example.com/public_html
sudo /usr/local/sbin/wp-audit
```

Либо передать путь явно:

```bash
sudo /usr/local/sbin/wp-audit /home/example/web/example.com/public_html
```

Если файл скачан без установки в `/usr/local/sbin`:

```bash
sudo ./wp-audit.sh /home/example/web/example.com/public_html
```

## Глубокое сканирование PHP

Режим `--deep` дополнительно ищет ряд высокорисковых PHP-конструкций:

```bash
sudo wp-audit --deep /home/example/web/example.com/public_html
```

или:

```bash
sudo ./wp-audit.sh --deep /home/example/web/example.com/public_html
```

Нахождение такого кода **не всегда означает заражение**. Результаты глубокого сканирования требуют ручной проверки.

## Где искать WordPress

Переданный каталог должен быть корнем установки WordPress и содержать как минимум:

```text
wp-admin/
wp-content/
wp-includes/
wp-config.php
```

Скрипт дополнительно проверяет наличие:

```text
wp-includes/version.php
```

Если путь не похож на корень WordPress, выполнение завершается с кодом `2`.

## Отчёты

При запуске от `root` отчёты сохраняются в `/root`.

Основной отчёт:

```text
/root/wp-security-audit-YYYYMMDD-HHMMSS.log
```

Файл с предлагаемыми командами исправления:

```text
/root/wp-security-audit-YYYYMMDD-HHMMSS.commands.txt
```

Если скрипт запущен не от `root`, файлы создаются в домашнем каталоге текущего пользователя.

Права на оба файла устанавливаются в `600`.

### Важно

Файл `*.commands.txt` нельзя выполнять вслепую.

Сначала сопоставьте каждую предлагаемую команду с соответствующей находкой в основном отчёте и убедитесь, что файл, плагин или конфигурация действительно являются нежелательными.

## Коды возврата

| Код | Значение |
|---:|---|
| `0` | критических находок высокой уверенности не обнаружено |
| `1` | обнаружены критические / высокоуверенные находки |
| `2` | ошибка использования или окружения |

Например:

```bash
sudo wp-audit --deep /var/www/example.com
echo $?
```

Это позволяет использовать скрипт в собственных системах мониторинга и автоматизации.

## Почему рекомендуется запуск от root

Некоторые проверки системного уровня доступны полностью только при запуске от `root`, например:

- `crontab` системного пользователя сайта;
- проверка его sudo-прав;
- доступ к части файлов;
- сохранение полного отчёта в `/root`.

При этом WP-CLI не запускается от `root` для сайта, принадлежащего другому пользователю: скрипт пытается выполнить такие команды от имени владельца webroot через `sudo -u`.

## Безопасное размещение на сервере

Не рекомендуется постоянно хранить аудит-скрипт внутри публичного каталога WordPress.

Хороший вариант:

```text
/usr/local/sbin/wp-audit
```

или:

```text
/root/bin/wp-audit.sh
```

Например:

```bash
mkdir -p /root/bin
install -m 700 wp-audit.sh /root/bin/wp-audit.sh
```

Запуск:

```bash
sudo /root/bin/wp-audit.sh --deep /home/example/web/example.com/public_html
```

Если скрипт расположен внутри дерева WordPress, он определит это, исключит себя из проверки контрольных сумм ядра и выведет рекомендацию после использования перенести его за пределы webroot.

## Рекомендуемая структура GitHub-репозитория

Самый простой вариант:

```text
wordpress-security-audit/
├── README.md
├── wp-audit.sh
└── LICENSE
```

При таком расположении прямая ссылка на файл выглядит так:

```text
https://raw.githubusercontent.com/USERNAME/REPOSITORY/main/wp-audit.sh
```

Например, если пользователь GitHub — `ivan`, а репозиторий называется `wordpress-security-audit`:

```text
https://raw.githubusercontent.com/ivan/wordpress-security-audit/main/wp-audit.sh
```

Её можно использовать непосредственно с `curl`:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ivan/wordpress-security-audit/main/wp-audit.sh \
  -o wp-audit.sh
```

## Одноразовый запуск без установки

Безопаснее сначала скачать файл, посмотреть его и только затем запускать:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/USERNAME/REPOSITORY/main/wp-audit.sh \
  -o /tmp/wp-audit.sh

less /tmp/wp-audit.sh
chmod 700 /tmp/wp-audit.sh
sudo /tmp/wp-audit.sh --deep /path/to/wordpress
```

Не рекомендуется использовать конструкцию вида:

```bash
curl URL | sudo bash
```

для административных скриптов, скачиваемых из сети: предварительный просмотр скачанного файла значительно безопаснее.

## Пример полного запуска

```bash
sudo wp-audit --deep /home/user/web/example.com/public_html
```

После завершения:

```bash
less /root/wp-security-audit-*.log
```

Просмотреть предлагаемые команды:

```bash
less /root/wp-security-audit-*.commands.txt
```

## Что означает чистый результат

Отсутствие критических находок не является доказательством полной безопасности сервера или сайта.

Например, отдельно могут требовать проверки:

- база данных WordPress;
- premium/custom плагины и темы, для которых нет официальных checksum;
- пользовательские PHP-приложения;
- другие сайты того же системного пользователя;
- системные службы;
- процессы и сетевые соединения;
- панель управления хостингом;
- SSH;
- утёкшие пароли, API-ключи и другие секреты.

После подтверждённого инцидента рекомендуется сменить:

- пароли администраторов WordPress;
- пароль базы данных;
- WordPress salts;
- учётные данные панели хостинга;
- SSH/API-ключи и другие потенциально раскрытые секреты.

Также следует обновить WordPress, плагины и темы до поддерживаемых исправленных версий.

## Лицензия

Перед публикацией проекта добавьте файл `LICENSE`.

Для небольшого open-source инструмента обычно удобно использовать MIT License, если вы хотите разрешить свободное использование, изменение и распространение кода с сохранением уведомления об авторских правах.

## Disclaimer

Скрипт предназначен для аудита собственных серверов и сайтов либо систем, на проверку которых у вас есть разрешение.

Все результаты требуют технической интерпретации. Автоматически найденный файл или фрагмент кода не следует удалять только на основании совпадения с одним правилом сканирования.
