#!/bin/sh

CONFIG_PATH="/opt/etc/HydraRoute/hrneo.conf"
DOMAIN_CONF="/opt/etc/HydraRoute/domain.conf"
PID_FILE="/var/run/hrneo.pid"
INIT_SCRIPT="/opt/etc/init.d/S99hrneo"
API_PORT=79
API_URL="http://localhost:${API_PORT}/rci/show/ip/policy/"

VPN_PREFIXES="tun tap wg ppp l2tp vless ss ssr vmess trojan nwg t2s"

KNOWN_DNS_IPS="8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 208.67.222.222 208.67.220.220 77.88.8.8 77.88.8.1 94.140.14.14 94.140.15.15"

log_info() {
    echo "[INFO] $1" >&2
}

log_warn() {
    echo "[WARN] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_success() {
    echo "[OK] $1" >&2
}

log_step() {
    echo "" >&2
    echo "==> $1" >&2
}

check_dependencies() {
    log_step "Проверка зависимостей"

    if ! command -v jq >/dev/null 2>&1; then
        log_warn "Пакет jq не установлен"
        log_info "Установка jq..."

        if opkg update && opkg install jq; then
            log_success "Пакет jq успешно установлен"
        else
            log_error "Не удалось установить jq"
            return 1
        fi
    else
        log_success "Пакет jq установлен"
    fi

    return 0
}

read_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        log_error "Файл конфигурации не найден: $CONFIG_PATH"
        return 1
    fi

    DIRECT_ROUTE_ENABLED=$(grep '^DirectRouteEnabled=' "$CONFIG_PATH" | cut -d'=' -f2)
    INTERFACE_FWMARK_START=$(grep '^InterfaceFwMarkStart=' "$CONFIG_PATH" | cut -d'=' -f2)
    INTERFACE_TABLE_START=$(grep '^InterfaceTableStart=' "$CONFIG_PATH" | cut -d'=' -f2)

    if [ -z "$DIRECT_ROUTE_ENABLED" ]; then
        DIRECT_ROUTE_ENABLED="true"
    fi

    if [ -z "$INTERFACE_FWMARK_START" ]; then
        INTERFACE_FWMARK_START="12289"
    fi

    if [ -z "$INTERFACE_TABLE_START" ]; then
        INTERFACE_TABLE_START="301"
    fi

    log_success "Конфигурация загружена (DirectRoute: $DIRECT_ROUTE_ENABLED)"

    return 0
}

check_domain_in_config() {
    local domain="$1"

    log_step "Проверка наличия домена в конфигурации"

    if [ ! -f "$DOMAIN_CONF" ]; then
        log_error "Файл $DOMAIN_CONF не найден"
        return 1
    fi

    local found=0
    local found_disabled=0
    local target_name=""

    while IFS= read -r line || [ -n "$line" ]; do
        line=$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')

        if [ -z "$line" ]; then
            continue
        fi

        local is_disabled=0
        case "$line" in
            \#*)
                is_disabled=1
                line=$(echo "$line" | sed 's/^#//' | sed 's/^[ \t]*//')
                ;;
        esac

        case "$line" in
            */*) ;;
            *) continue ;;
        esac

        local domains_part=$(echo "$line" | cut -d'/' -f1)
        local target_part=$(echo "$line" | cut -d'/' -f2- | cut -d',' -f1)

        local old_ifs="$IFS"
        IFS=','
        for d in $domains_part; do
            d=$(echo "$d" | sed 's/^[ \t]*//;s/[ \t]*$//')
            if [ "$d" = "$domain" ]; then
                if [ $is_disabled -eq 1 ]; then
                    found_disabled=1
                else
                    found=1
                    target_name="$target_part"
                fi
                IFS="$old_ifs"
                break
            fi
        done
        IFS="$old_ifs"

        if [ $found -eq 1 ] || [ $found_disabled -eq 1 ]; then
            break
        fi
    done < "$DOMAIN_CONF"

    if [ $found -eq 1 ]; then
        log_success "Домен найден в конфигурации"
        log_info "Назначен целевой объект: $target_name"
        echo "$target_name"
        return 0
    elif [ $found_disabled -eq 1 ]; then
        log_error "Домен '$domain' есть в Hydra Route, но отключен"
        log_info "Активируйте '$domain' в Web-интерфейсе Hydra Route"
        return 1
    else
        log_error "Домен '$domain' отсутствует в Hydra Route"
        log_info "Добавьте домен в Web-интерфейсе Hydra Route для его маршрутизации"
        return 1
    fi
}

classify_target() {
    local target="$1"

    log_step "Определение типа целевого объекта"

    if [ -d "/sys/class/net/$target" ]; then
        log_success "Целевой объект '$target' является сетевым интерфейсом"
        echo "interface"
    else
        log_success "Целевой объект '$target' является политикой доступа"
        echo "policy"
    fi
}

restart_service() {
    log_step "Перезапуск сервиса hrneo"

    if [ ! -x "$INIT_SCRIPT" ]; then
        log_error "Скрипт инициализации не найден или не исполняемый: $INIT_SCRIPT"
        return 1
    fi

    log_info "Выполняется перезапуск..."
    $INIT_SCRIPT restart >/dev/null 2>&1 || true

    log_info "Ожидание запуска сервиса (5 секунд)..."
    sleep 5

    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE" | tr -d '\n')
        if [ -d "/proc/$pid" ]; then
            log_success "Сервис успешно запущен (PID: $pid)"
        else
            log_error "PID файл существует, но процесс не запущен (stale PID: $pid)"
            return 1
        fi
    else
        log_error "PID файл не создан, сервис не запустился"
        return 1
    fi

    return 0
}

check_policy_created() {
    local policy_name="$1"

    log_step "Проверка создания политики в роутере"

    log_info "Запрос информации о политике '$policy_name'..."

    if ! command -v curl >/dev/null 2>&1; then
        log_warn "curl не установлен, используется альтернативный метод"

        if command -v ndmc >/dev/null 2>&1; then
            if ndmc -c "show ip policy $policy_name" >/dev/null 2>&1; then
                log_success "Политика '$policy_name' существует в роутере"
                return 0
            else
                log_error "Политика '$policy_name' не создана в роутере"
                return 1
            fi
        else
            log_warn "Невозможно проверить политику (отсутствуют curl и ndmc)"
            log_info "Пропуск проверки политики"
            return 0
        fi
    fi

    local response=$(curl -s "$API_URL" 2>/dev/null || echo "{}")

    if echo "$response" | jq -e ".\"$policy_name\"" >/dev/null 2>&1; then
        local mark=$(echo "$response" | jq -r ".\"$policy_name\".mark // empty")
        local description=$(echo "$response" | jq -r ".\"$policy_name\".description // empty")

        log_success "Политика '$policy_name' создана в роутере"
        [ -n "$mark" ] && [ "$mark" != "empty" ] && log_info "Mark ID: $mark"
        [ -n "$description" ] && [ "$description" != "empty" ] && log_info "Описание: $description"
        return 0
    else
        log_error "Политика '$policy_name' не найдена в роутере"
        return 1
    fi
}

get_interface_from_policy() {
    local policy_name="$1"

    log_step "Извлечение интерфейса из политики"

    if ! command -v curl >/dev/null 2>&1; then
        log_warn "curl не установлен, невозможно получить информацию об интерфейсе"
        log_info "Предполагается, что интерфейс настроен корректно"
        echo "unknown"
        return 0
    fi

    local response=$(curl -s "$API_URL" 2>/dev/null || echo "{}")

    local keenetic_interface=$(echo "$response" | jq -r ".\"$policy_name\" | .. | .route? // empty | .[] | select(.destination == \"0.0.0.0/0\") | .interface" 2>/dev/null | head -n1)

    if [ -z "$keenetic_interface" ] || [ "$keenetic_interface" = "null" ]; then
        log_warn "Интерфейс не указан в политике '$policy_name' или политика использует автоматический выбор"
        log_info "Пропуск проверки интерфейса для этой политики"
        echo "unknown"
        return 0
    fi

    log_info "Интерфейс Keenetic: $keenetic_interface"

    if command -v ndmc >/dev/null 2>&1; then
        local system_interface=$(ndmc -c "show interface $keenetic_interface system-name" 2>/dev/null | grep 'system-name:' | awk '{print $2}')

        if [ -n "$system_interface" ]; then
            log_success "Системное имя интерфейса: $system_interface"
            echo "$system_interface"
            return 0
        else
            log_warn "Не удалось получить системное имя интерфейса '$keenetic_interface'"
            log_info "Пропуск проверки интерфейса"
            echo "unknown"
            return 0
        fi
    else
        log_warn "ndmc не установлен, невозможно преобразовать имя интерфейса"
        log_info "Пропуск проверки интерфейса"
        echo "unknown"
        return 0
    fi
}

check_interface_exists() {
    local interface="$1"

    log_step "Проверка существования интерфейса"

    if [ ! -d "/sys/class/net/$interface" ]; then
        log_error "Интерфейс '$interface' отсутствует в системе"
        return 1
    fi

    log_success "Интерфейс '$interface' существует"

    return 0
}

check_vpn_protocol() {
    local interface="$1"

    log_step "Проверка типа VPN протокола"

    local is_vpn=0
    for prefix in $VPN_PREFIXES; do
        if echo "$interface" | grep -q "^${prefix}"; then
            is_vpn=1
            log_success "Интерфейс '$interface' определен как VPN (префикс: $prefix)"
            break
        fi
    done

    if [ $is_vpn -eq 0 ]; then
        log_warn "Интерфейс '$interface' не определен как VPN-подключение"
        log_info "Префикс интерфейса не соответствует известным VPN протоколам"
        log_info "Известные префиксы: $VPN_PREFIXES"
    fi

    return 0
}

check_vpn_connectivity() {
    local interface="$1"

    log_step "Проверка связности через VPN интерфейс"

    if ! command -v curl >/dev/null 2>&1; then
        log_info "curl не установлен, попытка установки..."
        if opkg update >/dev/null 2>&1 && opkg install curl >/dev/null 2>&1; then
            log_success "curl успешно установлен"
        else
            log_warn "Не удалось установить curl, пропуск проверки связности"
            return 0
        fi
    fi

    log_info "Проверка подключения через '$interface'..."

    local test_url="http://connectivitycheck.gstatic.com/generate_204"
    local response_code=$(curl -s -o /dev/null -w "%{http_code}" --interface "$interface" --connect-timeout 10 --max-time 15 "$test_url" 2>/dev/null)

    if [ "$response_code" = "204" ]; then
        log_success "Связь через интерфейс '$interface' работает"
    elif [ "$response_code" = "200" ]; then
        log_success "Связь через интерфейс '$interface' работает (HTTP 200)"
    elif [ -n "$response_code" ] && [ "$response_code" != "000" ]; then
        log_warn "Получен неожиданный ответ через '$interface': HTTP $response_code"
        log_info "Связь есть, но ответ нестандартный (возможно captive portal)"
    else
        log_error "Нет связи через интерфейс '$interface'"
        log_info "Возможные причины:"
        log_info "  - VPN подключение не установлено"
        log_info "  - Проблемы с маршрутизацией"
        log_info "  - Firewall блокирует исходящие соединения"
        return 1
    fi

    return 0
}

check_ipset_exists() {
    local ipset_name="$1"

    log_step "Проверка создания ipset"

    if ipset list "$ipset_name" >/dev/null 2>&1; then
        local count=$(ipset list "$ipset_name" | awk '/^Number of entries:/ {print $4; exit}')
        if [ -z "$count" ]; then
            count="0"
        fi
        log_success "IPSet '$ipset_name' создан (записей: $count)"
    else
        log_error "IPSet '$ipset_name' не создан"
        return 1
    fi

    local ipset_name_v6="${ipset_name}v6"
    if ipset list "$ipset_name_v6" >/dev/null 2>&1; then
        local count=$(ipset list "$ipset_name_v6" | awk '/^Number of entries:/ {print $4; exit}')
        if [ -z "$count" ]; then
            count="0"
        fi
        log_success "IPSet '$ipset_name_v6' создан (записей: $count)"
    else
        log_warn "IPSet '$ipset_name_v6' не создан (IPv6)"
    fi

    return 0
}

check_nflog_rules() {
    log_step "Проверка правил NFLOG для мониторинга DNS"

    local nflog_found_ipv4=0
    local nflog_found_ipv6=0

    if iptables -w -t mangle -S OUTPUT 2>/dev/null | grep -q -- "--nflog-group 100"; then
        nflog_found_ipv4=1
        log_success "Правила NFLOG для мониторинга DNS (IPv4) найдены"
    else
        log_error "Правила NFLOG для мониторинга DNS (IPv4) не найдены"
        log_info "DNS ответы не будут обрабатываться, IP не будут добавляться в ipset"
        return 1
    fi

    if ip6tables -w -t mangle -S OUTPUT 2>/dev/null | grep -q -- "--nflog-group 100"; then
        nflog_found_ipv6=1
        log_success "Правила NFLOG для мониторинга DNS (IPv6) найдены"
    else
        log_warn "Правила NFLOG для мониторинга DNS (IPv6) не найдены"
    fi

    return 0
}

check_iptables_rules() {
    local target_name="$1"
    local target_type="$2"

    log_step "Проверка правил iptables"

    local ipset_name="$target_name"
    local found_ipv4=0
    local found_ipv6=0

    if iptables -w -t mangle -S PREROUTING 2>/dev/null | grep -q -- "--match-set $ipset_name "; then
        found_ipv4=1
        log_success "Правила iptables для '$ipset_name' (IPv4) найдены"

        local rule_count=$(iptables -w -t mangle -S PREROUTING 2>/dev/null | grep -c -- "--match-set $ipset_name " || echo "0")
        log_info "Количество правил IPv4: $rule_count"
    else
        log_error "Правила iptables для '$ipset_name' (IPv4) не найдены"
        return 1
    fi

    if ip6tables -w -t mangle -S PREROUTING 2>/dev/null | grep -q -- "--match-set ${ipset_name}v6 "; then
        found_ipv6=1
        log_success "Правила ip6tables для '${ipset_name}v6' (IPv6) найдены"
    else
        log_warn "Правила ip6tables для '${ipset_name}v6' (IPv6) не найдены"
    fi

    return 0
}

resolve_domain() {
    local domain="$1"

    log_step "Проверка DNS разрешения домена"

    log_info "Разрешение домена '$domain'..."

    local ip_address=""

    if command -v nslookup >/dev/null 2>&1; then
        local nslookup_output=$(nslookup "$domain" 2>/dev/null)
        ip_address=$(echo "$nslookup_output" | awk 'BEGIN {found_name=0; ipv4=""; ipv6=""}
            /^Name:/ {found_name=1; next}
            found_name && /^Address [0-9]+:/ {
                ip=$3
                if (ip !~ /:/) {
                    if (ipv4 == "") ipv4=ip
                } else {
                    if (ipv6 == "") ipv6=ip
                }
            }
            END {
                if (ipv4 != "") print ipv4
                else if (ipv6 != "") print ipv6
            }')
    elif command -v host >/dev/null 2>&1; then
        ip_address=$(host "$domain" 2>/dev/null | awk '/has address/ {print $4; exit} /has IPv6 address/ {print $5; exit}')
    elif command -v dig >/dev/null 2>&1; then
        ip_address=$(dig +short "$domain" 2>/dev/null | grep -v ':' | head -n1)
        if [ -z "$ip_address" ]; then
            ip_address=$(dig +short "$domain" 2>/dev/null | head -n1)
        fi
    else
        log_error "Не найден ни один инструмент DNS разрешения (nslookup, host, dig)"
        return 1
    fi

    ip_address=$(echo "$ip_address" | head -n1 | tr -d '\n\r')

    if [ -z "$ip_address" ]; then
        log_error "Не удалось разрешить домен '$domain'"
        return 1
    fi

    log_info "Получен IP адрес: $ip_address"

    local br0_ip=$(ip addr show br0 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1)
    local all_dns_ips="127.0.0.1 0.0.0.0 $br0_ip $KNOWN_DNS_IPS"

    for dns_ip in $all_dns_ips; do
        if [ "$ip_address" = "$dns_ip" ]; then
            log_error "Домен разрешается некорректно (получен IP DNS сервера: $ip_address)"
            return 1
        fi
    done

    if echo "$ip_address" | grep -q '^10\.\|^192\.168\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[0-1]\.'; then
        log_error "Домен разрешается в приватный IP адрес: $ip_address"
        return 1
    fi

    if echo "$ip_address" | grep -qE '^(127\.|0\.0\.0\.0)'; then
        log_error "Домен разрешается в локальный/некорректный IP адрес: $ip_address"
        return 1
    fi

    log_success "Домен разрешается корректно в IP: $ip_address"
    echo "$ip_address"
}

check_ip_in_ipset() {
    local ipset_name="$1"
    local ip_address="$2"

    log_step "Проверка добавления IP в ipset"

    log_info "Ожидание обработки DNS ответа hrneo..."

    local max_attempts=5
    local attempt=0
    local found=0

    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))

        sleep 1

        if ipset test "$ipset_name" "$ip_address" >/dev/null 2>&1; then
            found=1
            break
        fi

        if [ $attempt -lt $max_attempts ]; then
            log_info "Попытка $attempt/$max_attempts - IP ещё не добавлен, ожидание..."
        fi
    done

    if [ $found -eq 1 ]; then
        log_success "IP адрес $ip_address добавлен в ipset '$ipset_name'"
    else
        log_error "IP адрес $ip_address НЕ добавлен в ipset '$ipset_name' после $max_attempts попыток"
        log_info "Возможные причины:"
        log_info "  - DNS запрос не прошел через роутер (проверьте настройки DNS на устройстве)"
        log_info "  - NFLOG мониторинг не работает (проверьте правила iptables OUTPUT)"
        log_info "  - Сервис hrneo не обрабатывает DNS ответы"
        return 1
    fi

    return 0
}

check_routing() {
    local ip_address="$1"
    local target_name="$2"
    local target_type="$3"

    log_step "Проверка конфигурации маршрутизации"

    if [ "$target_type" = "policy" ]; then
        if ! command -v curl >/dev/null 2>&1; then
            log_warn "curl не установлен, пропуск проверки конфигурации маршрутизации"
            return 0
        fi

        local response=$(curl -s "$API_URL" 2>/dev/null || echo "{}")
        local mark=$(echo "$response" | jq -r ".\"$target_name\".mark // empty" 2>/dev/null)
        local table=$(echo "$response" | jq -r ".\"$target_name\".table4 // empty" 2>/dev/null)
        local gateway=$(echo "$response" | jq -r ".\"$target_name\" | .. | .route? // empty | .[] | select(.destination == \"0.0.0.0/0\") | .gateway" 2>/dev/null | head -n1)
        local vpn_interface=$(echo "$response" | jq -r ".\"$target_name\" | .. | .route? // empty | .[] | select(.destination == \"0.0.0.0/0\") | .interface" 2>/dev/null | head -n1)

        log_success "Конфигурация политики '$target_name':"
        [ -n "$mark" ] && [ "$mark" != "empty" ] && log_info "  • fwmark: $mark"
        [ -n "$table" ] && [ "$table" != "empty" ] && log_info "  • Таблица маршрутизации: $table"
        [ -n "$vpn_interface" ] && [ "$vpn_interface" != "empty" ] && log_info "  • VPN интерфейс: $vpn_interface"
        [ -n "$gateway" ] && [ "$gateway" != "empty" ] && [ "$gateway" != "0.0.0.0" ] && log_info "  • Шлюз: $gateway"

    else
        local interface_gateway=""

        local route_via_interface=$(ip route show dev "$target_name" 2>/dev/null | grep 'via' | head -n1)
        if [ -n "$route_via_interface" ]; then
            interface_gateway=$(echo "$route_via_interface" | awk '{print $3}')
        fi

        if [ -z "$interface_gateway" ]; then
            local default_route=$(ip route show table all dev "$target_name" 2>/dev/null | grep 'default' | head -n1)
            if [ -n "$default_route" ]; then
                interface_gateway=$(echo "$default_route" | awk '{print $3}')
            fi
        fi

        log_success "Конфигурация интерфейса '$target_name':"
        [ -n "$interface_gateway" ] && log_info "  • Шлюз: $interface_gateway"
    fi

    echo "" >&2
    log_info "ВАЖНО: Диагностика на роутере не может проверить реальную маршрутизацию"
    log_info "трафика клиентских устройств, так как правила применяются только к"
    log_info "проходящему трафику (FORWARD), а не к трафику самого роутера (OUTPUT)."
    echo "" >&2
    log_info "Для проверки реальной маршрутизации выполните с клиентского устройства:"
    log_info "  tracert $domain"
    log_info "или"
    log_info "  traceroute $domain"
    echo "" >&2
    log_info "Ожидаемый результат: второй хоп должен быть VPN шлюзом."

    return 0
}

main() {
    echo "==========================================" >&2
    echo "  Диагностика Hydra Route Neo (hrneo)" >&2
    echo "==========================================" >&2
    echo "" >&2

    check_dependencies

    read_config

    printf "\nВведите домен для диагностики: " >&2
    read domain

    if [ -z "$domain" ]; then
        log_error "Домен не может быть пустым"
        exit 1
    fi

    target_name=$(check_domain_in_config "$domain") || exit 1

    target_type=$(classify_target "$target_name") || exit 1

    restart_service || exit 1

    if [ "$target_type" = "policy" ]; then
        check_policy_created "$target_name" || exit 1

        interface=$(get_interface_from_policy "$target_name") || exit 1

        if [ "$interface" != "unknown" ]; then
            check_interface_exists "$interface" || exit 1
            check_vpn_protocol "$interface" || exit 1
            check_vpn_connectivity "$interface" || exit 1
        fi
    else
        check_interface_exists "$target_name" || exit 1
        check_vpn_protocol "$target_name" || exit 1
        check_vpn_connectivity "$target_name" || exit 1
    fi

    check_ipset_exists "$target_name" || exit 1

    check_iptables_rules "$target_name" "$target_type" || exit 1

    check_nflog_rules || exit 1

    ip_address=$(resolve_domain "$domain") || exit 1

    check_ip_in_ipset "$target_name" "$ip_address" || exit 1

    check_routing "$ip_address" "$target_name" "$target_type" || exit 1

    echo "" >&2
    echo "==========================================" >&2
    log_success "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО"
    echo "==========================================" >&2
    echo "" >&2
    log_info "Конфигурация выборочной маршрутизации на роутере корректна."
    log_info "Все необходимые компоненты настроены и работают."
    echo "" >&2
    log_info "Для подтверждения корректной маршрутизации с клиентских устройств"
    log_info "выполните команду tracert/traceroute (см. выше)."
    echo "" >&2
    log_info "Если проблема сохраняется, проверьте настройки клиентского устройства:"
    log_info "  - DNS сервер должен указывать на роутер"
    log_info "  - Шлюз по умолчанию должен быть IP адресом роутера"
    log_info "  - На устройстве не должно быть собственного VPN или прокси"
    echo "" >&2
}

main
