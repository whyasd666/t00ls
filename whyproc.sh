#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
#  WHYPROC — CTF Process Monitor  |  /proc-based, no deps, no root required
# ══════════════════════════════════════════════════════════════════════════════

RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RED_B=$'\033[38;5;196m\033[1m'
RED_M=$'\033[38;5;197m'
RED_L=$'\033[38;5;203m'
RED_D=$'\033[38;5;160m'
RED_DK=$'\033[38;5;124m'
ORANGE=$'\033[38;5;208m\033[1m'
YELLOW=$'\033[38;5;226m'
WHITE=$'\033[97m'
GREY=$'\033[38;5;245m'
PINK=$'\033[38;5;204m'
GREEN=$'\033[38;5;82m'

COLS=$(tput cols 2>/dev/null || echo 120)

# ─── SPLASH ───────────────────────────────────────────────────────────────────
splash() {
    clear
    echo ""
    local art=(
        "██╗    ██╗██╗  ██╗██╗   ██╗██████╗ ██████╗  ██████╗  ██████╗"
        "██║    ██║██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝"
        "██║ █╗ ██║███████║ ╚████╔╝ ██████╔╝██████╔╝██║   ██║██║     "
        "██║███╗██║██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══██╗██║   ██║██║     "
        "╚███╔███╔╝██║  ██║   ██║   ██║     ██║  ██║╚██████╔╝╚██████╗"
        " ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝"
    )
    for line in "${art[@]}"; do
        local pad=$(( (COLS - 63) / 2 )); [[ $pad -lt 0 ]] && pad=0
        printf "%${pad}s${BOLD}${WHITE}%s${RESET}\n" "" "$line"
    done

    # drip effect — light red bleed below letters
    local drips=(
        "  ║       ║   ║      ╚██╗ ██╔╝  ██╔══╝   ██╔══╝  ║       ║"
        "   ║      ║    ║       ╚███╔╝    ██║       ██║    ║       ║"
        "    ╚══╝╚══╝    ╚═╝      ╚═╝      ╚═╝       ╚═╝  ╚══════╝"
    )
    for line in "${drips[@]}"; do
        local pad=$(( (COLS - 63) / 2 + 1 )); [[ $pad -lt 0 ]] && pad=0
        printf "%${pad}s${RED_L}${DIM}%s${RESET}\n" "" "$line"
    done

    echo ""
    local sub="[ CTF Process Monitor — /proc Edition ]"
    printf "%*s\n" $(( (COLS + ${#sub}) / 2 )) "${RED_B}${sub}${RESET}"
    local sub2="Catches cat · nano · vim · cron · ssh · short-lived procs"
    printf "%*s\n" $(( (COLS + ${#sub2}) / 2 )) "${RED_DK}${DIM}${sub2}${RESET}"
    echo ""

    # loading bar
    local bw=50
    local pad=$(( (COLS - bw - 10) / 2 )); [[ $pad -lt 0 ]] && pad=0
    printf "%${pad}s${RED_DK}[${RESET}" ""
    for ((i=0;i<bw;i++)); do printf "${RED_B}▓${RESET}"; sleep 0.012; done
    printf "${RED_DK}]${RESET} ${RED_B}${BOLD}GO${RESET}\n\n"
    sleep 0.2
}

# ─── HEADER ───────────────────────────────────────────────────────────────────
print_header() {
    local border; border=$(printf '═%.0s' $(seq 1 $COLS))
    printf "${RED_DK}%s${RESET}\n" "$border"
    printf "${RED_B}  ▌WHYPROC▐  ${RED_D}CTF Edition${RESET}"
    printf "${GREY}%*s${RESET}\n" $((COLS - 22)) "$(date '+%F %T')"
    printf "${RED_DK}%s${RESET}\n" "$border"
    printf "  ${RED_L}${BOLD}%-9s %-7s %-14s %-13s %-10s %s${RESET}\n" \
           "TIME" "PID" "USER" "PTS/TTY" "EVENT" "COMMAND"
    printf "${RED_DK}%s${RESET}\n" "$(printf '─%.0s' $(seq 1 $COLS))"
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────
get_cmdline() {
    local pid=$1
    tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | sed 's/ $//'
}

get_comm() {
    cat /proc/$1/comm 2>/dev/null
}

get_exe() {
    readlink /proc/$1/exe 2>/dev/null
}

get_tty() {
    local pid=$1 tty
    tty=$(readlink /proc/$pid/fd/0 2>/dev/null)
    if [[ "$tty" == /dev/pts/* || "$tty" == /dev/tty* ]]; then
        echo "${tty#/dev/}"
    else
        # fallback: parse stat field 7 (tty_nr)
        local tty_nr; tty_nr=$(awk '{print $7}' /proc/$pid/stat 2>/dev/null)
        if [[ -n "$tty_nr" && "$tty_nr" != "0" ]]; then
            local maj=$(( (tty_nr >> 8) & 0xfff ))
            local min=$(( tty_nr & 0xff ))
            local found; found=$(ls -l /dev/pts/ 2>/dev/null \
                | awk -v mj="$maj" -v mn="$min" \
                  'NR>1 && $5==mj"," && $NF+0==mn {print "pts/"$NF}' | head -1)
            echo "${found:-?}"
        else
            echo "?"
        fi
    fi
}

get_user() {
    local pid=$1 uid
    uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null)
    if [[ -n "$uid" ]]; then
        getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "uid$uid"
    else echo "?"; fi
}

# ─── CLASSIFY ─────────────────────────────────────────────────────────────────
classify() {
    local cmd="$1" exe="$2"
    local base; base=$(basename "$exe" 2>/dev/null)

    # Reverse shells / web shells
    if echo "$cmd" | grep -qP '(bash\s+-i\s+>&|/dev/tcp/|mkfifo|socat\s+exec|nc\s+-e|ncat\s+-e)'; then
        echo "REVSH|${RED_B}"; return
    fi
    if echo "$cmd" | grep -qP '(php\s+-r|python[23]?\s+-c.*socket|perl\s+-e|shell_exec|passthru\(|cmd=|exec=)'; then
        echo "WSHELL|${RED_B}"; return
    fi

    # SSH
    if echo "$exe$cmd" | grep -qP '(sshd|/ssh$|ssh\s+-l\s)'; then
        echo "SSH|${ORANGE}"; return
    fi

    # Privilege escalation
    if echo "$base$cmd" | grep -qP '^(sudo|su|pkexec|doas)\b|chmod\s+[46][0-9]{3}'; then
        echo "PRIV|${ORANGE}"; return
    fi

    # File viewers / editors (the main ones missing before)
    case "$base" in
        cat|less|more|tail|head|tac|bat) echo "VIEW|${PINK}"; return ;;
        nano|vim|vi|nvim|emacs|micro|joe|ne) echo "EDIT|${PINK}"; return ;;
        grep|awk|sed|cut|sort|uniq|tr|wc) echo "PROC|${RED_L}"; return ;;
        find|locate|fd|fzf) echo "FIND|${RED_L}"; return ;;
        strings|xxd|hexdump|od|file|binwalk) echo "BINFMT|${YELLOW}"; return ;;
        diff|cmp|patch|delta) echo "DIFF|${RED_L}"; return ;;
    esac

    # File ops
    case "$base" in
        cp|mv|rm|mkdir|rmdir|touch|ln|install) echo "FILE|${RED_M}"; return ;;
        tar|zip|unzip|gzip|bzip2|xz|7z|zstd) echo "ARCH|${RED_M}"; return ;;
        rsync|scp|sftp) echo "XFER|${ORANGE}"; return ;;
    esac

    # Network
    case "$base" in
        curl|wget|fetch|httpie) echo "HTTP|${RED_M}"; return ;;
        nc|ncat|netcat|socat)   echo "NET|${RED_M}"; return ;;
        nmap|masscan|zmap)      echo "SCAN|${RED_B}"; return ;;
        tcpdump|tshark|dumpcap) echo "PCAP|${YELLOW}"; return ;;
        ss|netstat|lsof)        echo "SOCK|${RED_D}"; return ;;
        iptables|nft|ufw)       echo "FW|${ORANGE}"; return ;;
    esac

    # Cron / scheduled
    if echo "$exe$cmd" | grep -qP '(cron|atd|anacron)'; then
        echo "CRON|${YELLOW}"; return
    fi

    # Python / scripting interpreters — show full cmd
    case "$base" in
        python*|ruby|perl|php|lua|node|nodejs) echo "SCRIPT|${GREEN}"; return ;;
        bash|sh|zsh|fish|dash|ksh)             echo "SHELL|${RED_D}"; return ;;
    esac

    echo "EXEC|${RED_DK}"
}

# ─── PRINT EVENT ──────────────────────────────────────────────────────────────
print_event() {
    local ts pid user tty tag col cmd
    ts=$1 pid=$2 user=$3 tty=$4 tag=$5 col=$6
    shift 6; cmd="$*"
    local cmd_w=$(( COLS - 58 ))
    [[ $cmd_w -lt 20 ]] && cmd_w=20
    cmd="${cmd:0:$cmd_w}"
    printf "  ${GREY}%-9s${RESET}${RED_M}%-7s${RESET}${RED_L}%-14s${RESET}${RED_D}%-13s${RESET}${col}%-10s${RESET}${WHITE}%s${RESET}\n" \
        "$ts" "$pid" "${user:0:13}" "${tty:0:12}" "$tag" "$cmd"
}

# ─── MAIN SCAN LOOP ───────────────────────────────────────────────────────────
# Strategy: snapshot all PIDs → compare → emit NEW ones immediately
# Sleep only 50ms between polls = catches nearly all short-lived procs

declare -A SEEN      # pid → cmdline hash to detect re-exec
declare -A SEEN_CONN # for network connections

scan_once() {
    local now; now=$(date '+%H:%M:%S')
    for piddir in /proc/[0-9]*/; do
        local pid="${piddir%/}"; pid="${pid##*/}"
        [[ ! -d "/proc/$pid" ]] && continue

        local cmd; cmd=$(get_cmdline "$pid")
        [[ -z "$cmd" ]] && cmd=$(get_comm "$pid")
        [[ -z "$cmd" ]] && continue

        # Use pid+cmd as key — catches re-exec of same pid
        local key="${pid}:${cmd}"
        [[ "${SEEN[$key]+_}" ]] && continue
        SEEN[$key]=1

        local exe; exe=$(get_exe "$pid")
        local user; user=$(get_user "$pid")
        local tty; tty=$(get_tty "$pid")

        local result; result=$(classify "$cmd" "$exe")
        local tag="${result%%|*}"
        local col="${result##*|}"

        print_event "$now" "$pid" "$user" "$tty" "$tag" "$col" "$cmd"
    done
}

scan_network() {
    local now; now=$(date '+%H:%M:%S')
    local f
    for f in /proc/net/tcp /proc/net/tcp6; do
        [[ -f "$f" ]] || continue
        while read -r sl local rem state _ _ _ _ _ _ inode _; do
            [[ "$sl" == "sl" ]] && continue
            [[ "$state" != "01" && "$state" != "0A" ]] && continue
            [[ "${SEEN_CONN[$inode]+_}" ]] && continue
            SEEN_CONN[$inode]=1

            local lport; lport=$(printf '%d' "0x${local##*:}" 2>/dev/null)
            local rport; rport=$(printf '%d' "0x${rem##*:}" 2>/dev/null)
            local lhex="${local%%:*}" rhex="${rem%%:*}"

            # decode little-endian hex IP
            decode_ip4() {
                local h=$1
                printf '%d.%d.%d.%d' \
                    $((16#${h:6:2})) $((16#${h:4:2})) \
                    $((16#${h:2:2})) $((16#${h:0:2})) 2>/dev/null
            }

            local lip rip
            if [[ ${#lhex} -le 8 ]]; then
                lip=$(decode_ip4 "$lhex"); rip=$(decode_ip4 "$rhex")
            else
                lip="[ipv6]"; rip="[ipv6]"
            fi

            local tag="NET" col="$RED_M"
            [[ "$lport" == "22" || "$rport" == "22" ]] && tag="SSH-CON" && col="$ORANGE"
            [[ "$lport" == "80" || "$lport" == "443" || "$lport" == "8080" ]] && tag="HTTP" && col="$RED_L"
            [[ "$state" == "0A" ]] && tag="LISTEN"

            print_event "$now" "net" "-" "-" "$tag" "$col" \
                "${lip}:${lport} → ${rip}:${rport}"
        done < "$f"
    done
}

scan_logins() {
    local now; now=$(date '+%H:%M:%S')
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local key; key="${line// /}"
        [[ "${SEEN[who:$key]+_}" ]] && continue
        SEEN[who:$key]=1
        local user pts from
        user=$(awk '{print $1}' <<< "$line")
        pts=$(awk '{print $2}' <<< "$line")
        from=$(awk '{print $NF}' <<< "$line")
        print_event "$now" "-" "$user" "$pts" "LOGIN" "$ORANGE" "from $from"
    done < <(who 2>/dev/null)
}

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
main() {
    [[ $EUID -ne 0 ]] && printf "${ORANGE}[!]${RESET} ${WHITE}No root — some procs may be hidden. sudo recommended.${RESET}\n" && sleep 1

    splash
    print_header

    printf "  ${RED_DK}${BOLD}[★] Polling /proc every 50ms — Press Ctrl+C to exit${RESET}\n"
    printf "${RED_DK}%s${RESET}\n" "$(printf '─%.0s' $(seq 1 $COLS))"

    local cycle=0
    while true; do
        scan_once
        scan_network
        scan_logins

        (( cycle++ ))
        if (( cycle % 200 == 0 )); then
            printf "${RED_DK}%s${RESET}\n" "$(printf '─%.0s' $(seq 1 $COLS))"
            printf "  ${GREY}[↻ $(date '+%H:%M:%S') — ${#SEEN[@]} unique events captured]${RESET}\n"
            printf "${RED_DK}%s${RESET}\n" "$(printf '─%.0s' $(seq 1 $COLS))"
        fi

        sleep 0.05
    done
}

trap 'printf "\n${RED_B}[✘] WHYPROC stopped.${RESET}\n"; exit 0' INT TERM
main "$@"
