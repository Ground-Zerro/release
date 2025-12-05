#!/bin/sh

cd /tmp

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
	echo "Stop and delete opkg" >>"$LOG"
	[ -f /opt/etc/init.d/S99adguardhome ] && /opt/etc/init.d/S99adguardhome stop
	[ -f /opt/etc/init.d/S99hpanel ] && /opt/etc/init.d/S99hpanel stop
	[ -f /opt/etc/init.d/S99hrpanel ] && /opt/etc/init.d/S99hrpanel stop
	[ -f /opt/etc/init.d/S99hrneo ] && /opt/etc/init.d/S99hrneo stop
	[ -f /opt/etc/init.d/S99hrweb ] && /opt/etc/init.d/S99hrweb stop
	
	opkg remove --force-depends hrweb hrneo hydraroute adguardhome-go ipset iptables jq node node-npm
}

files_uninstall() {
	echo "Delete files and path" >>"$LOG"
	
	rm -f /opt/etc/ndm/ifstatechanged.d/010-bypass-table.sh
	rm -f /opt/etc/ndm/ifstatechanged.d/011-bypass6-table.sh
	rm -f /opt/etc/ndm/netfilter.d/010-bypass.sh
	rm -f /opt/etc/ndm/netfilter.d/011-bypass6.sh
	rm -f /opt/etc/ndm/netfilter.d/010-hydra.sh
	rm -f /opt/etc/ndm/netfilter.d/015-hrneo.sh
	rm -f /opt/etc/ndm/netfilter.d/016-hrweb.sh
	rm -f /opt/etc/init.d/S52ipset
	rm -f /opt/etc/init.d/S52hydra
	rm -f /opt/etc/init.d/S99hpanel
	rm -f /opt/etc/init.d/S99hrpanel
	rm -f /opt/etc/init.d/S99hrneo
	rm -f /opt/etc/init.d/S99hrweb
	rm -f /opt/etc/init.d/S98hr
	rm -f /opt/etc/opkg/customfeeds.conf
	rm -f /opt/var/log/AdGuardHome.log
	rm -f /opt/bin/agh
	rm -f /opt/bin/hr
	rm -f /opt/bin/hrpanel
	rm -f /opt/bin/neo
	
	if [ -d "/opt/etc/HydraRoute" ] && [ "/opt/etc/HydraRoute" != "/" ]; then
		rm -rf /opt/etc/HydraRoute
	fi
	if [ -d "/opt/etc/AdGuardHome" ] && [ "/opt/etc/AdGuardHome" != "/" ]; then
		rm -rf /opt/etc/AdGuardHome
	fi
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
	echo "Delete hr.net host" >>"$LOG"
	ndmc -c "no ip host hr.net"
	echo "System DNS on" >>"$LOG"
	ndmc -c 'opkg no dns-override'
	ndmc -c 'system configuration save'
	sleep 2
}

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

SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null)"
if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
	(sleep 3 && rm -f "$SCRIPT_PATH" && reboot) &
else
	(sleep 3 && reboot) &
fi

exit 0
