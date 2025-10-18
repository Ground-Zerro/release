#!/bin/sh

# Служебные функции и переменные
LOG="/opt/var/log/HydraRoute.log"
printf "\n%s Удаление\n" "$(date "+%Y-%m-%d %H:%M:%S")" >>"$LOG" 2>&1
## анимация
animation() {
	local pid=$1
	local message=$2
	local spin='-\|/'

	echo -n "$message... "

	while kill -0 $pid 2>/dev/null; do
		for i in $(seq 0 3); do
			echo -ne "\b${spin:$i:1}"
			usleep 100000  # 0.1 сек
		done
	done

  echo -e "\b✔ Готово!"
}

# удаление пакетов
opkg_uninstall() {
	/opt/etc/init.d/S99adguardhome stop
	/opt/etc/init.d/S99hpanel stop
	/opt/etc/init.d/S99hrpanel stop
	/opt/etc/init.d/S99hrneo stop
	opkg remove hrneo hydraroute adguardhome-go ipset iptables jq node-npm node
}

# удаление файлов
files_uninstall() {
	FILES="
	/opt/etc/ndm/ifstatechanged.d/010-bypass-table.sh
	/opt/etc/ndm/ifstatechanged.d/011-bypass6-table.sh
	/opt/etc/ndm/netfilter.d/010-bypass.sh
	/opt/etc/ndm/netfilter.d/011-bypass6.sh
	/opt/etc/ndm/netfilter.d/010-hydra.sh
	/opt/etc/ndm/netfilter.d/015-hrneo.sh
	/opt/etc/init.d/S52ipset
	/opt/etc/init.d/S52hydra
	/opt/etc/init.d/S99hpanel
	/opt/etc/init.d/S99hrpanel
	/opt/etc/init.d/S99hrneo
	/opt/etc/init.d/S98hr
	/opt/var/log/AdGuardHome.log
	/opt/bin/agh
	/opt/bin/hr
	/opt/bin/hrpanel
	/opt/bin/neo
	"

	for FILE in $FILES; do
		[ -f "$FILE" ] && { chmod 777 "$FILE" || true; rm -f "$FILE"; }
	done

	[ -d /opt/etc/HydraRoute ] && { chmod -R 777 /opt/etc/HydraRoute || true; rm -rf /opt/etc/HydraRoute; }
	[ -d /opt/etc/AdGuardHome ] && { chmod -R 777 /opt/etc/AdGuardHome || true; rm -rf /opt/etc/AdGuardHome; }
}

# удаление политик
policy_uninstall() {
	for suffix in 1st 2nd 3rd; do
		ndmc -c "no ip policy HydraRoute$suffix"
	done
	ndmc -c "no ip policy HydraRoute"
	ndmc -c 'system configuration save'
	sleep 2
}

# включение IPv6 и DNS провайдера
enable_ipv6_and_dns() {
  interfaces=$(curl -kfsS "http://localhost:79/rci/show/interface/" | jq -r '
    to_entries[] | 
    select(.value.defaultgw == true or .value.via != null) | 
    if .value.via then "\(.value.id) \(.value.via)" else "\(.value.id)" end
  ')

  for line in $interfaces; do
    set -- $line
    iface=$1
    via=$2

    ndmc -c "interface $iface ipv6 address auto"
    ndmc -c "interface $iface ip name-servers"

    if [ -n "$via" ]; then
      ndmc -c "interface $via ipv6 address auto"
      ndmc -c "interface $via ip name-servers"
    fi
  done

  ndmc -c 'system configuration save'
  sleep 2
}

# включение системного DNS сервера
dns_on() {
	ndmc -c 'opkg no dns-override'
	ndmc -c 'system configuration save'
	sleep 2
}

#main
enable_ipv6_and_dns >>"$LOG" 2>&1 &
animation $! "Включение IPv6 и DNS провайдера"

opkg_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление opkg пакетов"

( files_uninstall >>"$LOG" 2>&1; exit 0 ) &
animation $! "Удаление файлов, созданных HydraRoute"

policy_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление политик HydraRoute"

dns_on >>"$LOG" 2>&1 &
animation $! "Включение системного DNS сервера"

echo "Удаление завершено (╥_╥)"
echo "Перезагрузка..."
[ -f "$0" ] && rm "$0"
reboot

