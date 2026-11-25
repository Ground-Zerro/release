#!/bin/sh

cd /tmp

LOG="/opt/var/log/HydraRoute.log"
printf "\n%s Удаление\n" "$(date "+%Y-%m-%d %H:%M:%S")" > "$LOG" 2>&1
HR_IFACES="/tmp/hr-uninstall.ifaces"

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

hr_collect() {
	echo "Collect HydraRoute interfaces" >>"$LOG"
	: >"$HR_IFACES"
	for meta in /opt/etc/HydraRoute/subs/*.json; do
		[ -f "$meta" ] && grep -oE '"(iface|rciIface)" *: *"[^"]+"' "$meta" | sed 's/.*"\([^"]*\)"$/\1/' >>"$HR_IFACES"
	done
	{
		[ -f /opt/etc/Phobos/registry ] && sed 's/^/@@/' /opt/etc/Phobos/registry
		ndmc -c 'show running-config' 2>/dev/null
	} | tr -d '\r' | awk '
		/^@@/ { if (split(substr($0, 3), f, "|") >= 8 && f[8] != "") phobos[f[8]] = 1; next }
		/^interface / { i = $2 }
		/^ +description / {
			d = $0
			sub(/^ +description /, "", d)
			gsub(/"/, "", d)
			if (d ~ /^xRay-/ || (i ~ /^(Wireguard|Proxy)[0-9]+$/ && (d ~ /^Phobos-/ || d in phobos))) print i
		}
	' >>"$HR_IFACES"
	cat "$HR_IFACES"
}

services_uninstall() {
	echo "Stop services" >>"$LOG"
	for init in \
		/opt/etc/init.d/S99adguardhome /opt/etc/init.d/S99hpanel /opt/etc/init.d/S99hrpanel \
		/opt/etc/init.d/S99hrneo /opt/etc/init.d/D99hrneo /opt/etc/init.d/S99hrweb \
		/opt/etc/init.d/S09hrdns /opt/etc/init.d/S09hrweb-dns /opt/etc/init.d/S10smartdns-webui \
		/opt/etc/init.d/S24xray /opt/etc/init.d/D24xray /opt/etc/init.d/S[0-9]*wg-obfuscator; do
		[ -f "$init" ] && "$init" stop
	done
	for signal in TERM KILL; do
		for proc in hrweb hrneo hrdns-ui hrdns hrweb-dns smartdns-webui xray; do
			killall -$signal "$proc" 2>/dev/null
		done
		for obfuscator in /opt/bin/wg-obfuscator*; do
			[ -f "$obfuscator" ] && killall -$signal "${obfuscator##*/}" 2>/dev/null
		done
		sleep 2
	done
	ndmc -c 'no opkg dns-override'
}

opkg_uninstall() {
	echo "Delete opkg" >>"$LOG"
	opkg remove hrdns hrweb smartdns-webui hrneo xray xray-core ipset iptables jq hydraroute adguardhome-go node-npm node
}

ndm_uninstall() {
	echo "Delete HydraRoute policies, interfaces and hosts, system DNS on" >>"$LOG"
	ndmc -c 'show running-config' 2>/dev/null | awk '/^ip policy /{print $3}' | tr -d '\r' | grep -vE '^Policy[0-9]+$' | while read -r policy; do
		[ -n "$policy" ] && ndmc -c "no ip policy $policy"
	done
	tr -d '\r ' <"$HR_IFACES" | sort -u | while read -r iface; do
		[ -n "$iface" ] || continue
		case "$iface" in
			OpkgTun*) ndmc -c "no ip route default $iface" ;;
		esac
		ndmc -c "no interface $iface"
	done
	for host in hr.net hrweb-verify.net hrweb-verify.internal; do
		ndmc -c "no ip host $host"
	done
	ndmc -c 'no opkg dns-override'
	ndmc -c 'system configuration save'
	rm -f "$HR_IFACES"
	sleep 2
}

files_uninstall() {
	echo "Delete files and path" >>"$LOG"
	rm -rf \
		/opt/etc/ndm/ifstatechanged.d/010-bypass-table.sh /opt/etc/ndm/ifstatechanged.d/011-bypass6-table.sh \
		/opt/etc/ndm/ifstatechanged.d/015-hrneo.sh \
		/opt/etc/ndm/netfilter.d/010-bypass.sh /opt/etc/ndm/netfilter.d/011-bypass6.sh \
		/opt/etc/ndm/netfilter.d/010-hydra.sh /opt/etc/ndm/netfilter.d/015-hrneo.sh /opt/etc/ndm/netfilter.d/016-hrweb.sh \
		/opt/etc/init.d/S52ipset /opt/etc/init.d/S52hydra /opt/etc/init.d/S98hr \
		/opt/etc/init.d/S99hpanel /opt/etc/init.d/S99hrpanel /opt/etc/init.d/S99hrneo /opt/etc/init.d/D99hrneo \
		/opt/etc/init.d/S99hrweb /opt/etc/init.d/S24xray /opt/etc/init.d/D24xray \
		/opt/etc/init.d/S09hrdns /opt/etc/init.d/S09hrweb-dns /opt/etc/init.d/S10smartdns-webui \
		/opt/etc/init.d/S[0-9]*wg-obfuscator \
		/opt/etc/opkg/customfeeds.conf \
		/opt/bin/agh /opt/bin/hr /opt/bin/hrpanel /opt/bin/neo /opt/bin/hrweb /opt/bin/hrneo \
		/opt/bin/smartdns-webui /opt/bin/wg-obfuscator* \
		/opt/sbin/hrdns /opt/sbin/.hrdns.new /opt/sbin/hrweb-dns* /opt/sbin/xray \
		/opt/var/log/AdGuardHome.log /opt/var/log/LOGhrneo.log* \
		/var/run/hrweb.pid /var/run/hrneo.pid /var/run/hrneo.sock \
		/var/run/hrdns.pid /run/hrdns.pid /var/run/hrdns-ui.sock \
		/var/run/hrweb-dns.pid /var/run/hrweb-dns.sock /var/run/smartdns-webui* \
		/tmp/hrdns* /tmp/hrweb-dns* /tmp/hrweb-update.log /tmp/hrweb-monitor-down.json /tmp/smartdns* \
		/var/log/smartdns /var/cache/smartdns /var/lib/smartdns \
		/opt/etc/HydraRoute /opt/etc/AdGuardHome /opt/etc/xray /opt/etc/Phobos /opt/etc/smartdns-webui \
		/opt/var/lib/hrdns /opt/var/lib/smartdns-webui
	if [ -f /opt/etc/init.d/rc.unslung ]; then
		sed -i '/^\[ \$ACTION = start \] && sleep 10$/d' /opt/etc/init.d/rc.unslung
	fi
}

hr_collect >>"$LOG" 2>&1 &
animation $! "Поиск подключений HydraRoute"

services_uninstall >>"$LOG" 2>&1 &
animation $! "Остановка служб HydraRoute, DNS, xRay и Phobos"

opkg_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление opkg пакетов"

ndm_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление политик, подключений и хостов, включение системного DNS"

files_uninstall >>"$LOG" 2>&1 &
animation $! "Удаление файлов, созданных HydraRoute"

rm -f "$LOG"

echo "Удаление завершено (╥_╥)"
echo "Перезагрузка через 5 секунд..."

SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null)"
if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
	(sleep 3 && rm -f "$SCRIPT_PATH" && reboot) &
else
	(sleep 3 && reboot) &
fi

exit 0
