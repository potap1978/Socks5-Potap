#!/bin/bash

# Безопасный скрипт управления Dante Proxy
# Удаляет пользователей при удалении прокси

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Пути и маркеры
INSTALL_MARKER="/etc/dante_proxy_installed"
PROXY_USERS_FILE="/etc/dante_proxy_users"
DANTE_CONFIG="/etc/danted.conf"

# Список АБСОЛЮТНО ЗАПРЕЩЕННЫХ для удаления пользователей
# Эти пользователи НИКОГДА не будут удалены
PROTECTED_USERS=(
    # Основные системные
    "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp"
    "www-data" "backup" "list" "irc" "gnats" "nobody"
    
    # Сетевые и системные службы
    "dhcpcd" "dnsmasq" "avahi" "avahi-autoipd" "kernoops" "rtkit" "saned" 
    "whoopsie" "speech-dispatcher" "usbmux" "messagebus" "syslog" "tss"
    "pollinate" "_apt" "Debian-snmp"
    
    # Веб-серверы
    "nginx" "apache" "www" "wwwrun"
    
    # Другие сервисы
    "docker" "sshd" "ftp" "squid" "postfix" "dovecot" "bind" "named"
    "libvirt" "qemu" "kvm" "vbox" "proxy" "socks" "dante"
)

# Проверка на root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Ошибка: скрипт должен быть запущен с правами root${NC}"
        exit 1
    fi
}

# Очистка экрана
clear_screen() {
    printf "\033[H\033[J"
}

# Проверка абсолютно защищенного пользователя
is_absolutely_protected_user() {
    local user="$1"
    
    # Проверяем точное совпадение
    for protected in "${PROTECTED_USERS[@]}"; do
        if [ "$user" = "$protected" ]; then
            return 0
        fi
    done
    
    # Проверяем системные пользователи по UID (UID < 1000)
    local uid=$(id -u "$user" 2>/dev/null || echo "1000")
    if [ "$uid" -lt 1000 ]; then
        return 0
    fi
    
    return 1
}

# Проверка, создан ли пользователь этим скриптом
is_proxy_user() {
    local user="$1"
    
    # Проверяем, есть ли пользователь в файле proxy пользователей
    if [ -f "$PROXY_USERS_FILE" ] && grep -q "^$user$" "$PROXY_USERS_FILE" 2>/dev/null; then
        return 0  # Это proxy пользователь
    fi
    
    return 1  # Не proxy пользователь
}

# Получение списка пользователей прокси (только созданных скриптом)
get_proxy_users() {
    if [ -f "$PROXY_USERS_FILE" ]; then
        cat "$PROXY_USERS_FILE"
    else
        echo ""
    fi
}

# Добавление пользователя в список
add_to_proxy_users() {
    local user="$1"
    if [ ! -f "$PROXY_USERS_FILE" ] || ! grep -q "^$user$" "$PROXY_USERS_FILE" 2>/dev/null; then
        echo "$user" >> "$PROXY_USERS_FILE"
        sort -u "$PROXY_USERS_FILE" -o "$PROXY_USERS_FILE"
    fi
}

# Удаление пользователя из списка
remove_from_proxy_users() {
    local user="$1"
    if [ -f "$PROXY_USERS_FILE" ]; then
        grep -v "^$user$" "$PROXY_USERS_FILE" > "${PROXY_USERS_FILE}.tmp"
        mv "${PROXY_USERS_FILE}.tmp" "$PROXY_USERS_FILE"
    fi
}

# Генерация случайного порта
generate_random_port() {
    while :; do
        port=$((RANDOM % 64512 + 1024))
        if ! ss -tuln | awk '{print $4}' | grep -q ":$port$"; then
            echo $port
            return
        fi
    done
}

# Получение внешнего IP
get_external_ip() {
    local ip
    ip=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || 
         curl -4 -s --connect-timeout 5 api.ipify.org 2>/dev/null || 
         curl -4 -s --connect-timeout 5 icanhazip.com 2>/dev/null ||
         ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    echo "$ip"
}

# Показать меню
show_menu() {
    clear_screen
    echo
    echo -e "${RED}=== БЕЗОПАСНОЕ УПРАВЛЕНИЕ DANTE PROXY ===${NC}"
    echo
    
    if [ -f "$INSTALL_MARKER" ]; then
        port=$(head -n 1 "$INSTALL_MARKER")
        interface=$(tail -n 1 "$INSTALL_MARKER" 2>/dev/null)
        
        # Проверяем статус службы
        if systemctl is-active --quiet danted; then
            status="${GREEN}● Активен${NC}"
        else
            status="${RED}● Неактивен${NC}"
        fi
        
        echo -e "${GREEN}✓ Прокси установлен${NC}"
        echo -e "  Статус: $status"
        echo -e "  Порт: $port"
        [ -n "$interface" ] && echo -e "  Интерфейс: $interface"
        echo
        
        # Показываем пользователи
        users=$(get_proxy_users)
        user_count=$(echo "$users" | wc -w)
        echo -e "${BLUE}Пользователей: $user_count${NC}"
        if [ -n "$users" ]; then
            echo "$users" | tr ' ' '\n' | while read user; do
                echo -e "  ${GREEN}•${NC} $user"
            done
        fi
        echo
        
        echo -e "${BLUE}1. Добавить пользователя${NC}"
        echo -e "${BLUE}2. Удалить пользователя${NC}"
        echo -e "${BLUE}3. Сменить пароль пользователя${NC}"
        echo -e "${BLUE}4. Показать данные подключения${NC}"
        echo -e "${BLUE}5. Перезапустить прокси${NC}"
        echo -e "${BLUE}6. Удалить прокси${NC}"
        echo -e "${BLUE}7. Выход${NC}"
    else
        echo -e "${YELLOW}✗ Прокси не установлен${NC}"
        echo
        echo -e "${BLUE}1. Установить Dante Proxy${NC}"
        echo -e "${BLUE}2. Выход${NC}"
    fi
    echo
}

# Установка Dante Proxy
install_proxy() {
    clear_screen
    echo
    echo -e "${RED}=== УСТАНОВКА DANTE PROXY ===${NC}"
    echo
    
    # Проверка установлен ли уже dante
    if dpkg -l | grep -q "dante-server"; then
        echo -e "${YELLOW}Dante уже установлен. Пропускаем установку пакетов.${NC}"
    else
        echo -e "${YELLOW}Установка необходимых пакетов...${NC}"
        apt update && apt install -y dante-server
        if [ $? -ne 0 ]; then
            echo -e "${RED}Ошибка при установке пакетов${NC}"
            sleep 2
            return
        fi
    fi
    
    # Выбор интерфейса
    echo -e "${YELLOW}Выбор сетевого интерфейса:${NC}"
    echo
    
    # Получаем список интерфейсов с IP
    interfaces=$(ip -o -4 addr show | awk '{print $2, $4}' | cut -d'/' -f1)
    
    if [ -z "$interfaces" ]; then
        echo -e "${RED}Не найдены сетевые интерфейсы с IP адресами${NC}"
        sleep 2
        return
    fi
    
    i=1
    declare -A iface_map
    while IFS= read -r line; do
        iface=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        echo -e "  ${BLUE}$i.${NC} $iface (${GREEN}$ip${NC})"
        iface_map[$i]="$iface"
        ((i++))
    done <<< "$interfaces"
    
    echo -e "  ${BLUE}$i.${NC} Все интерфейсы (0.0.0.0)"
    iface_map[$i]="all"
    
    echo
    read -p "Выберите интерфейс (1-$i): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "$i" ]; then
        echo -e "${RED}Неверный выбор${NC}"
        sleep 1
        return
    fi
    
    INTERFACE="${iface_map[$choice]}"
    
    # Выбор порта
    echo
    echo -e "${YELLOW}Выбор порта:${NC}"
    echo
    echo -e "  1. Автоматический выбор свободного порта"
    echo -e "  2. Ввести порт вручную"
    echo
    read -p "Выберите вариант (1-2): " port_choice
    
    case $port_choice in
        1)
            PORT=$(generate_random_port)
            echo -e "${GREEN}✓ Выбран порт: $PORT${NC}"
            ;;
        2)
            while :; do
                read -p "Введите порт (1024-65535): " PORT
                if [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ]; then
                    if ss -tuln | grep -q ":$PORT "; then
                        echo -e "${RED}Порт $PORT занят${NC}"
                    else
                        echo -e "${GREEN}✓ Порт $PORT свободен${NC}"
                        break
                    fi
                else
                    echo -e "${RED}Неверный порт${NC}"
                fi
            done
            ;;
        *)
            echo -e "${RED}Неверный выбор${NC}"
            return
            ;;
    esac
    
    # Создание конфигурации
    echo
    echo -e "${YELLOW}Создание конфигурации...${NC}"
    
    if [ "$INTERFACE" = "all" ]; then
        external_iface="0.0.0.0"
        internal_iface="0.0.0.0"
    else
        external_iface="$INTERFACE"
        internal_iface="0.0.0.0"
    fi
    
    cat > "$DANTE_CONFIG" << EOF
logoutput: syslog
internal: $internal_iface port = $PORT
external: $external_iface
clientmethod: none
socksmethod: username
user.privileged: root
user.notprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
    socksmethod: username
}
EOF
    
    # Настройка firewall
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo -e "${YELLOW}Настройка UFW...${NC}"
        ufw allow "$PORT/tcp"
    fi
    
    # Запуск и включение службы
    systemctl restart danted
    systemctl enable danted
    
    # Сохранение информации об установке
    echo "$PORT" > "$INSTALL_MARKER"
    echo "$INTERFACE" >> "$INSTALL_MARKER"
    
    # Создание файла пользователей если его нет
    touch "$PROXY_USERS_FILE"
    
    echo
    echo -e "${GREEN}✓ Dante Proxy успешно установлен!${NC}"
    echo
    echo -e "${YELLOW}Информация для подключения:${NC}"
    echo -e "  Тип: ${GREEN}SOCKS5${NC}"
    echo -e "  Аутентификация: ${GREEN}логин/пароль${NC}"
    
    IP=$(get_external_ip)
    echo -e "  IP: ${GREEN}$IP${NC}"
    echo -e "  Порт: ${GREEN}$PORT${NC}"
    echo
    read -p "Нажмите Enter для продолжения..."
}

# Добавление пользователя
add_user() {
    clear_screen
    echo
    echo -e "${RED}=== ДОБАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ===${NC}"
    echo
    
    if [ ! -f "$INSTALL_MARKER" ]; then
        echo -e "${RED}Прокси не установлен${NC}"
        sleep 1
        return
    fi
    
    while :; do
        read -p "Введите имя пользователя: " username
        
        # Проверка имени
        if [ -z "$username" ]; then
            echo -e "${RED}Имя пользователя не может быть пустым${NC}"
            continue
        fi
        
        # Проверка на абсолютно защищенного пользователя
        if is_absolutely_protected_user "$username"; then
            echo -e "${RED}Ошибка: '$username' - системный пользователь, выберите другое имя${NC}"
            continue
        fi
        
        # Проверка существования
        if id "$username" &>/dev/null; then
            echo -e "${RED}Пользователь '$username' уже существует${NC}"
            
            # Проверяем, является ли этот пользователь системным
            if is_absolutely_protected_user "$username"; then
                echo -e "${RED}Это системный пользователь, нельзя использовать${NC}"
                continue
            fi
            
            read -p "Использовать существующего пользователя? (y/N): " use_existing
            if [[ "$use_existing" != "y" && "$use_existing" != "Y" ]]; then
                continue
            fi
            
            # Проверяем, не proxy ли это пользователь
            if is_proxy_user "$username"; then
                echo -e "${YELLOW}Пользователь уже является proxy пользователем${NC}"
                echo -e "${GREEN}Пользователь '$username' добавлен в список proxy${NC}"
                add_to_proxy_users "$username"
                show_connection_info "$username" "[пароль уже установлен]"
                read -p "Нажмите Enter для продолжения..."
                return
            fi
        else
            # Создание пользователя - используем -m чтобы создать домашнюю директорию
            # и гарантировать, что это не системный пользователь
            useradd -m -s /bin/false "$username"
            if [ $? -ne 0 ]; then
                echo -e "${RED}Ошибка при создании пользователя${NC}"
                continue
            fi
        fi
        
        break
    done
    
    # Установка пароля (только для новых пользователей или при согласии)
    if ! is_proxy_user "$username"; then
        while :; do
            read -sp "Введите пароль: " password
            echo
            read -sp "Повторите пароль: " password2
            echo
            
            if [ "$password" != "$password2" ]; then
                echo -e "${RED}Пароли не совпадают${NC}"
            elif [ -z "$password" ]; then
                echo -e "${RED}Пароль не может быть пустым${NC}"
            else
                break
            fi
        done
        
        # Установка пароля
        echo "$username:$password" | chpasswd
    else
        password="[уже установлен]"
    fi
    
    # Добавление в список прокси пользователей
    add_to_proxy_users "$username"
    
    echo
    echo -e "${GREEN}✓ Пользователь '$username' создан/добавлен${NC}"
    
    # Показать данные подключения
    show_connection_info "$username" "$password"
    
    read -p "Нажмите Enter для продолжения..."
}

# Показать информацию для подключения
show_connection_info() {
    local username="$1"
    local password="$2"
    
    if [ ! -f "$INSTALL_MARKER" ]; then
        return
    fi
    
    PORT=$(head -n 1 "$INSTALL_MARKER")
    IP=$(get_external_ip)
    
    echo
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BLUE}Сервер:${NC} ${GREEN}$IP${NC}"
    echo -e "${BLUE}Порт:${NC}   ${GREEN}$PORT${NC}"
    echo -e "${BLUE}Логин:${NC}  ${GREEN}$username${NC}"
    if [ "$password" != "[уже установлен]" ]; then
        echo -e "${BLUE}Пароль:${NC} ${GREEN}$password${NC}"
    else
        echo -e "${BLUE}Пароль:${NC} ${YELLOW}[уже установлен]${NC}"
    fi
    echo
    echo -e "${BLUE}Формат для браузеров:${NC}"
    if [ "$password" != "[уже установлен]" ]; then
        echo -e "${GREEN}$IP:$PORT:$username:$password${NC}"
        echo -e "${GREEN}socks5://$username:$password@$IP:$PORT${NC}"
    else
        echo -e "${GREEN}$IP:$PORT:$username:[ваш_пароль]${NC}"
        echo -e "${GREEN}socks5://$username:[ваш_пароль]@$IP:$PORT${NC}"
    fi
    echo
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Важно: Сохраните эти данные! Пароль не может быть восстановлен.${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
}

# Удаление пользователя
delete_user() {
    clear_screen
    echo
    echo -e "${RED}=== УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ===${NC}"
    echo
    
    users=$(get_proxy_users)
    
    if [ -z "$users" ]; then
        echo -e "${YELLOW}Нет пользователей для удаления${NC}"
        sleep 1
        return
    fi
    
    echo -e "${BLUE}Выберите пользователя:${NC}"
    echo
    
    i=1
    declare -A user_map
    for user in $users; do
        echo -e "  ${BLUE}$i.${NC} $user"
        user_map[$i]="$user"
        ((i++))
    done
    
    echo -e "  ${BLUE}0.${NC} Отмена"
    echo
    
    read -p "Выберите номер: " choice
    
    if [ "$choice" -eq 0 ] 2>/dev/null; then
        return
    fi
    
    if [ -z "${user_map[$choice]}" ]; then
        echo -e "${RED}Неверный выбор${NC}"
        sleep 1
        return
    fi
    
    username="${user_map[$choice]}"
    
    # Проверка на абсолютно защищенного пользователя
    if is_absolutely_protected_user "$username"; then
        echo -e "${RED}ОШИБКА БЕЗОПАСНОСТИ: '$username' - системный пользователь${NC}"
        echo -e "${YELLOW}Удаление невозможно!${NC}"
        sleep 3
        return
    fi
    
    echo
    echo -e "${YELLOW}Будет удален пользователь: $username${NC}"
    echo -e "${YELLOW}Это действие удалит пользователя и его домашнюю директорию!${NC}"
    echo
    
    read -p "Удалить пользователя '$username'? (y/N): " confirm
    
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        # Удаление из списка прокси
        remove_from_proxy_users "$username"
        
        # Удаление пользователя системы с домашней директорией
        userdel -r "$username" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Пользователь '$username' и его домашняя директория удалены${NC}"
        else
            echo -e "${YELLOW}⚠ Не удалось удалить пользователя '$username'${NC}"
            echo -e "${YELLOW}Пользователь удален из списка proxy, но может остаться в системе${NC}"
        fi
    else
        echo -e "${YELLOW}Удаление отменено${NC}"
    fi
    
    sleep 1
}

# Смена пароля
change_password() {
    clear_screen
    echo
    echo -e "${RED}=== СМЕНА ПАРОЛЯ ===${NC}"
    echo
    
    users=$(get_proxy_users)
    
    if [ -z "$users" ]; then
        echo -e "${YELLOW}Нет пользователей${NC}"
        sleep 1
        return
    fi
    
    echo -e "${BLUE}Выберите пользователя:${NC}"
    echo
    
    i=1
    declare -A user_map
    for user in $users; do
        echo -e "  ${BLUE}$i.${NC} $user"
        user_map[$i]="$user"
        ((i++))
    done
    
    echo -e "  ${BLUE}0.${NC} Отмена"
    echo
    
    read -p "Выберите номер: " choice
    
    if [ "$choice" -eq 0 ] 2>/dev/null; then
        return
    fi
    
    if [ -z "${user_map[$choice]}" ]; then
        echo -e "${RED}Неверный выбор${NC}"
        sleep 1
        return
    fi
    
    username="${user_map[$choice]}"
    
    # Смена пароля
    echo
    echo -e "${YELLOW}Смена пароля для пользователя: $username${NC}"
    echo
    
    # Используем passwd для смены пароля
    passwd "$username"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Пароль изменен${NC}"
        
        # Показать обновленные данные (без пароля)
        PORT=$(head -n 1 "$INSTALL_MARKER" 2>/dev/null)
        IP=$(get_external_ip)
        
        if [ -n "$PORT" ] && [ -n "$IP" ]; then
            echo
            echo -e "${YELLOW}Обновленные данные подключения:${NC}"
            echo -e "${GREEN}Сервер: $IP${NC}"
            echo -e "${GREEN}Порт: $PORT${NC}"
            echo -e "${GREEN}Логин: $username${NC}"
            echo -e "${RED}Пароль: [установлен новый пароль]${NC}"
            echo
            echo -e "${YELLOW}Формат:${NC} socks5://$username:[НОВЫЙ_ПАРОЛЬ]@$IP:$PORT"
        fi
    else
        echo -e "${RED}✗ Ошибка при смене пароля${NC}"
    fi
    
    read -p "Нажмите Enter для продолжения..."
}

# Показать данные подключения для всех
show_all_connections() {
    clear_screen
    echo
    echo -e "${RED}=== ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ ===${NC}"
    echo
    
    if [ ! -f "$INSTALL_MARKER" ]; then
        echo -e "${RED}Прокси не установлен${NC}"
        sleep 1
        return
    fi
    
    PORT=$(head -n 1 "$INSTALL_MARKER")
    IP=$(get_external_ip)
    
    echo -e "${BLUE}Общие данные:${NC}"
    echo -e "  Сервер: ${GREEN}$IP${NC}"
    echo -e "  Порт:   ${GREEN}$PORT${NC}"
    echo -e "  Тип:    ${GREEN}SOCKS5${NC}"
    echo
    
    users=$(get_proxy_users)
    
    if [ -z "$users" ]; then
        echo -e "${YELLOW}Нет пользователей${NC}"
    else
        echo -e "${BLUE}Пользователи:${NC}"
        for user in $users; do
            echo -e "  ${GREEN}•${NC} $user"
        done
        echo
        echo -e "${YELLOW}Формат для подключения:${NC}"
        echo -e "${GREEN}socks5://логин:пароль@$IP:$PORT${NC}"
        echo
        echo -e "${YELLOW}Для смены пароля выберите пункт 3 в главном меню${NC}"
        echo
        echo -e "${CYAN}Важно: Пароли хранятся в зашифрованном виде.${NC}"
        echo -e "${CYAN}Для восстановления доступа нужно установить новый пароль.${NC}"
    fi
    
    echo
    read -p "Нажмите Enter для продолжения..."
}

# Перезапуск прокси
restart_proxy() {
    clear_screen
    echo
    echo -e "${RED}=== ПЕРЕЗАПУСК ПРОКСИ ===${NC}"
    echo
    
    if [ ! -f "$INSTALL_MARKER" ]; then
        echo -e "${RED}Прокси не установлен${NC}"
        sleep 1
        return
    fi
    
    systemctl restart danted
    
    if systemctl is-active --quiet danted; then
        echo -e "${GREEN}✓ Прокси перезапущен${NC}"
    else
        echo -e "${RED}✗ Ошибка при перезапуске${NC}"
        echo
        echo -e "${YELLOW}Последние логи:${NC}"
        journalctl -u danted -n 10 --no-pager
    fi
    
    echo
    read -p "Нажмите Enter для продолжения..."
}

# Безопасное удаление прокси С пользователями
uninstall_proxy() {
    clear_screen
    echo
    echo -e "${RED}=== УДАЛЕНИЕ DANTE PROXY ===${NC}"
    echo
    
    if [ ! -f "$INSTALL_MARKER" ]; then
        echo -e "${YELLOW}Прокси не установлен${NC}"
        sleep 1
        return
    fi
    
    echo -e "${YELLOW}ВНИМАНИЕ! КРИТИЧЕСКОЕ УДАЛЕНИЕ!${NC}"
    echo -e "${YELLOW}Это действие:${NC}"
    echo -e "  1. Остановит службу Dante"
    echo -e "  2. Удалит конфигурационные файлы"
    echo -e "  3. ${GREEN}НЕ УДАЛИТ системных пользователей${NC}"
    echo -e "  4. ${RED}УДАЛИТ ВСЕХ proxy пользователей из системы${NC}"
    echo -e "  5. ${RED}УДАЛИТ домашние директории пользователей${NC}"
    echo -e "  6. ${RED}УДАЛИТ все файлы прокси${NC}"
    echo
    
    read -p "Вы уверены, что хотите полностью удалить Dante Proxy? (y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}Удаление отменено${NC}"
        sleep 1
        return
    fi
    
    # Получаем порт
    PORT=$(head -n 1 "$INSTALL_MARKER")
    
    # Останавливаем службу
    systemctl stop danted
    systemctl disable danted
    
    # Удаляем правило UFW
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw delete allow "$PORT/tcp" 2>/dev/null
    fi
    
    # Удаляем proxy пользователей
    if [ -f "$PROXY_USERS_FILE" ]; then
        echo
        echo -e "${YELLOW}Удаление proxy пользователей...${NC}"
        while read -r username; do
            if [ -n "$username" ] && ! is_absolutely_protected_user "$username"; then
                # Пытаемся удалить пользователя с домашней директорией
                if userdel -r "$username" 2>/dev/null; then
                    echo -e "${GREEN}✓ Удален пользователь: $username${NC}"
                else
                    # Если не удалось удалить с -r, пробуем без домашней директории
                    if userdel "$username" 2>/dev/null; then
                        echo -e "${YELLOW}⚠ Пользователь удален, но домашняя директория осталась: $username${NC}"
                    else
                        echo -e "${RED}✗ Не удалось удалить пользователя: $username${NC}"
                    fi
                fi
            elif [ -n "$username" ]; then
                echo -e "${YELLOW}⚠ Пропущен системный пользователь: $username${NC}"
            fi
        done < "$PROXY_USERS_FILE"
        echo -e "${GREEN}✓ Все proxy пользователи удалены${NC}"
    else
        echo -e "${YELLOW}Файл с пользователями не найден${NC}"
    fi
    
    # Удаляем конфигурационные файлы
    rm -f "$DANTE_CONFIG"
    rm -f "$INSTALL_MARKER"
    rm -f "$PROXY_USERS_FILE"
    
    echo
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}✓ Dante Proxy полностью удален!${NC}"
    echo -e "${GREEN}✓ Конфигурационные файлы удалены${NC}"
    echo -e "${GREEN}✓ Пользователи proxy удалены${NC}"
    echo -e "${GREEN}✓ Домашние директории удалены${NC}"
    echo -e "${GREEN}✓ Система очищена${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo
    echo -e "${YELLOW}Для повторной установки запустите скрипт заново.${NC}"
    echo
    
    read -p "Нажмите Enter для завершения..."
    exit 0
}

# Главный цикл
main() {
    check_root
    
    while true; do
        show_menu
        
        if [ -f "$INSTALL_MARKER" ]; then
            read -p "Выберите действие (1-7): " choice
            
            case $choice in
                1) add_user ;;
                2) delete_user ;;
                3) change_password ;;
                4) show_all_connections ;;
                5) restart_proxy ;;
                6) uninstall_proxy ;;
                7) 
                    echo -e "${YELLOW}Выход...${NC}"
                    echo
                    exit 0
                    ;;
                *) 
                    echo -e "${RED}Неверный выбор${NC}"
                    sleep 1
                    ;;
            esac
        else
            read -p "Выберите действие (1-2): " choice
            
            case $choice in
                1) install_proxy ;;
                2) 
                    echo -e "${YELLOW}Выход...${NC}"
                    echo
                    exit 0
                    ;;
                *) 
                    echo -e "${RED}Неверный выбор${NC}"
                    sleep 1
                    ;;
            esac
        fi
    done
}

# Запуск скрипта
main
