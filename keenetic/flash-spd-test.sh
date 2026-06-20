#!/bin/sh
# Entware/Keenetic storage speedtest with device selection and multi-size runs

set -u

# ---------- helpers ----------

# Print to stderr
err() { printf "%s\n" "$*" >&2; }

# Safe integer division with 1 decimal using awk: NUM/DEN -> "X.Y"
div1() {
    # usage: div1 NUM DEN
    awk 'BEGIN{n='"$1"'; d='"$2"'; if (d<1) d=1; printf "%.1f", n/d }'
}

# Humanize MB/s (one decimal)
mbps() {
    # usage: mbps SIZE_MB DUR_S
    SIZE_MB=$1; DUR=$2
    # avoid zero without if: add 1 if DUR==0
    DUR=$(( DUR + (DUR==0) ))
    div1 "$SIZE_MB" "$DUR"
}

# Get epoch seconds
now_s() {
    date +%s
}

# Measure dd op: args: MODE(write|read) SIZE_MB FILE
measure_dd() {
    MODE="$1"
    SZ="$2"
    FILE="$3"

    case "$MODE" in
        write)
            START=$(now_s)
            # conv=fsync у BusyBox dd — валидно; гарантируем запись на диск
            dd if=/dev/zero of="$FILE" bs=1M count="$SZ" conv=fsync >/dev/null 2>&1
            sync
            END=$(now_s)
            ;;
        read)
            START=$(now_s)
            dd if="$FILE" of=/dev/null bs=1M count="$SZ" >/dev/null 2>&1
            END=$(now_s)
            ;;
        *)
            err "Unknown mode: $MODE"; return 2 ;;
    esac

    DUR=$(( END - START ))
    # защита от деления на ноль без if
    DUR=$(( DUR + (DUR==0) ))
    printf "%s" "$DUR"
}

# Summaries (track min/max/avg via sums)
init_stats() {
    SUM_W=0 SUM_R=0 CNT=0
    MIN_W=0 MAX_W=0 MIN_R=0 MAX_R=0
}

update_stats() {
    # args: w_speed_str r_speed_str
    WS="$1"; RS="$2"
    CNT=$((CNT+1))
    # суммируем в сотых, чтобы избегать плавающей точки в оболочке
    WS100=$(printf "%s" "$WS" | awk '{printf "%d",$1*100}')
    RS100=$(printf "%s" "$RS" | awk '{printf "%d",$1*100}')
    SUM_W=$((SUM_W + WS100))
    SUM_R=$((SUM_R + RS100))
    # min/max (строковые в десятичной — используем awk для сравнения)
    if [ "$CNT" -eq 1 ]; then
        MIN_W="$WS"; MAX_W="$WS"; MIN_R="$RS"; MAX_R="$RS"
    else
        MIN_W=$(awk 'BEGIN{a='"$WS"';b='"$MIN_W"';print (a<b)?a:b}')
        MAX_W=$(awk 'BEGIN{a='"$WS"';b='"$MAX_W"';print (a>b)?a:b}')
        MIN_R=$(awk 'BEGIN{a='"$RS"';b='"$MIN_R"';print (a<b)?a:b}')
        MAX_R=$(awk 'BEGIN{a='"$RS"';b='"$MAX_R"';print (a>b)?a:b}')
    fi
}

print_summary() {
    AVG_W=$(awk 'BEGIN{s='"$SUM_W"';c='"$CNT"';printf "%.1f", (c? s/100.0/c : 0)}')
    AVG_R=$(awk 'BEGIN{s='"$SUM_R"';c='"$CNT"';printf "%.1f", (c? s/100.0/c : 0)}')

    echo
    echo "=== Итоги (${CNT} теста) ==="
    printf "Средняя запись: %s MB/s | Мин: %s | Макс: %s\n" "$AVG_W" "$MIN_W" "$MAX_W"
    printf "Среднее чтение: %s MB/s | Мин: %s | Макс: %s\n" "$AVG_R" "$MIN_R" "$MAX_R"
}

# ---------- detect & pick device ----------

# Составляем список только реальных блок-устройств /dev/* (исключая tmpfs/overlay/loop и т.п.)
# Используем df -P для стабильного парсинга (POSIX), -k чтобы всё в KiB.
LIST_FILE="/tmp/stor_list.$$"
trap 'rm -f "$LIST_FILE"' EXIT HUP INT TERM

i=0
df -Pk | awk 'NR>1 && $1 ~ "^/dev/" {print $1, $6, $4}' | while read -r DEV MNT AVAIL_KB; do
    # Фильтры: игнорируем корень, если нужно, и очевидные системные точки монтирования
    case "$MNT" in
        /proc|/sys|/dev|/run) continue ;;
    esac
    i=$((i+1))
    AVAIL_H=$(df -hP "$MNT" | awk 'NR==2{print $4}')
    printf "%d\t%s\t%s\t%s\t%s\n" "$i" "$DEV" "$MNT" "$AVAIL_KB" "$AVAIL_H"
done > "$LIST_FILE"

if ! [ -s "$LIST_FILE" ]; then
    err "Не найдены подходящие накопители (/dev/*)."
    exit 1
fi

echo "Доступные накопители:"
awk -F '\t' '{printf "  %d) %s на %s (свободно %s)\n", $1, $2, $3, $5}' "$LIST_FILE"

printf "Выберите номер: "
read -r CHOICE

# Проверка ввода: цифра и присутствует в списке
case "$CHOICE" in
    ''|*[!0-9]*)
        err "Неверный выбор."
        exit 1
        ;;
esac

SEL_LINE=$(awk -F '\t' '$1=='"$CHOICE"'{print; found=1} END{if(!found) exit 1}' "$LIST_FILE") || {
    err "Выбранный номер отсутствует."
    exit 1
}

DEV=$(printf "%s" "$SEL_LINE" | awk -F '\t' '{print $2}')
MNT=$(printf "%s" "$SEL_LINE" | awk -F '\t' '{print $3}')
AVAIL_KB=$(printf "%s" "$SEL_LINE" | awk -F '\t' '{print $4}')
AVAIL_MB=$(awk 'BEGIN{printf "%d", '"$AVAIL_KB"'/1024}')

echo
echo "Вы выбрали: $DEV, точка монтирования: $MNT, свободно: ${AVAIL_MB} MB"

# ---------- decide base size ----------

BASE_MB=200
if   [ "$AVAIL_MB" -lt 50 ];  then
    err "Недостаточно свободного места (< 50 MB). Отмена."
    exit 1
elif [ "$AVAIL_MB" -lt 100 ]; then
    BASE_MB=50
elif [ "$AVAIL_MB" -lt 200 ]; then
    BASE_MB=100
else
    BASE_MB=200
fi

# ---------- test sizes ----------

SIZE1=$BASE_MB
SIZE2=$(( BASE_MB / 2 ))
SIZE3=$(( BASE_MB / 4 ))
# гарантируем минимум 1 MB
[ "$SIZE2" -lt 1 ] && SIZE2=1
[ "$SIZE3" -lt 1 ] && SIZE3=1

TESTFILE="$MNT/entware_speedtest.bin"

echo
echo "=== Speedtest на $MNT (база: ${BASE_MB} MB) ==="
printf "План тестов (MB): %d, %d, %d\n" "$SIZE1" "$SIZE2" "$SIZE3"

init_stats

run_case() {
    SZ="$1"
    echo
    echo "[*] Тест записи: ${SZ} MB"
    DUR_W=$(measure_dd write "$SZ" "$TESTFILE")
    SPEED_W=$(mbps "$SZ" "$DUR_W")
    printf "  Время записи: %ss | Скорость записи: %s MB/s\n" "$DUR_W" "$SPEED_W"

    echo "[*] Тест чтения: ${SZ} MB"
    DUR_R=$(measure_dd read "$SZ" "$TESTFILE")
    SPEED_R=$(mbps "$SZ" "$DUR_R")
    printf "  Время чтения: %ss | Скорость чтения: %s MB/s\n" "$DUR_R" "$SPEED_R"

    update_stats "$SPEED_W" "$SPEED_R"

    # очищаем файл после каждого кейса, чтобы гарантировать место под следующий
    rm -f "$TESTFILE" 2>/dev/null
    sync
}

run_case "$SIZE1"
run_case "$SIZE2"
run_case "$SIZE3"

print_summary

echo
echo "[*] Готово."
