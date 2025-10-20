#!/bin/sh
LOG="/opt/var/log/HydraRoute.log"
printf "\n%s Удаление\n" "$(date "+%Y-%m-%d %H:%M:%S")" > "$LOG" 2>&1

animation() {
	local pid="$1"
	local message="$2"
	local spin='-\|/'
	local i=0
	printf "%s... " "$message"
	while kill -0 "$pid" 2>/dev/null; do
		i=$((i % 4))
		printf "\b%s" "$(echo "$spin" | cut -c$((i + 1)))"
		i=$((i + 1))
		usleep 100000
	done
	printf "\b✔ Готово!\n"
}

opkg_uninstall() {
	[ -f /opt/etc/init.d/S99adguardhome ] && /opt/etc/init.d/S99adguardhome stop
	[ -f /opt/etc/init.d/S99hpanel ] && /opt/etc/init.d/S99hpanel stop
	[ -f /opt/etc/init.d/S99hrpanel ] && /opt/etc/init.d/S99hrpanel stop
	[ -f /opt/etc/init.d/S99hrneo ] && /opt/etc/init.d/S99hrneo stop
	
	for pkg in hrneo hydraroute adguardhome-go ipset iptables jq node-npm node; do
		if opkg list-installed | grep -q "^$pkg "; then
			opkg remove "$pkg"
		fi
	done
}

files_uninstall() {
	echo "Delete files and path" >>"$LOG"
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
		[ -f "$FILE" ] && rm -f "$FILE"
	done
	
	[ -d /opt/etc/HydraRoute ] && rm -rf /opt/etc/HydraRoute
	[ -d /opt/etc/AdGuardHome ] && rm -rf /opt/etc/AdGuardHome
}

policy_uninstall() {
	echo "Policy uninstall" >>"$LOG"
	for suffix in 1st 2nd 3rd; do
		ndmc -c "no ip policy HydraRoute$suffix" || true
	done
	for suffix in 1 2 3; do
		ndmc -c "no ip policy HR$suffix" || true
	done
	ndmc -c 'no ip policy HydraRoute' || true
	ndmc -c 'system configuration save'
	sleep 2
}

dns_on() {
	echo "DoT add" >>"$LOG"
	if ndmc -c show version | grep -oq 'dns-tls'; then
		ndmc -c dns tls upstream 8.8.8.8 sni dns.google
		ndmc -c dns tls upstream 9.9.9.9 sni dns.quad9.net
	fi
	echo "System DNS on" >>"$LOG"
	ndmc -c 'opkg no dns-override'
	ndmc -c 'system configuration save'
	sleep 2
}

# main
opkg_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление opkg пакетов"

policy_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление политик HydraRoute"

files_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление файлов, созданных HydraRoute"

dns_on >>"$LOG" 2>&1 &
animation $! "Включение системного DNS сервера"

echo "Удаление завершено (╥_╥)"
echo "Перезагрузка через 5 секунд..."

SCRIPT_PATH="$0"
(sleep 3 && rm -f "$SCRIPT_PATH" && reboot) &
exit 0