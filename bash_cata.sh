#!/usr/bin/env bash
#
# required packages: jq, grepcidr, tmux;
#
# Bashcata Variables;
ROUTER="" # mikrotik ip;
LOGIN="" # user for connect to mikrotik;
PRIVATEKEY="/root/.ssh/mik_rsa" # private key for ssh;
FW_LIST="idps_alert" # name firewall list;
FW_TIMEOUT="7" # days ban ip;
WHITELIST_NETWORKS="" # networks: a.b.c.d/xy, a.b.c.d-e.f.g.h, a.b.c.d;
WHITELIST_SIGNATURE_ID="" # suricata signature_id: through a space;

# - #
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
ALERTS_FILE="/var/log/suricata/alerts.json"
PID_SURICATA="$(pidof suricata)"
MARK_IP="${SCRIPT_DIR}/mark.ip"
# - #

# Initialization TMUX session;
if ! tmux has-session -t mbi &> /dev/null; then
    tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}"" &
    # wait for last background process to finish;
    local w_pid="$!" ; wait "$w_pid"
fi

# Check files;
if [ ! -e "${MARK_IP}" ]; then touch "${MARK_IP}" ; fi

# Setting the logger utility function;
function logger() {
    find "${SCRIPT_DIR}"/ -maxdepth 1 -name "*.log" -size +100k -exec rm -f {} \;
    echo -e "[$(date "+%d.%m.%Y / %H:%M:%S")]: $1" >> "${SCRIPT_DIR}"/"bash_cata.log"
}

# Tail Conveyor;
tail -q -f "${ALERTS_FILE}" --pid="$PID_SURICATA" -n 500 | while read -r LINE; do

# Parsing Json file via jq;
alerts="$(echo "${LINE}" | jq -c '[.timestamp, .src_ip, .dest_ip, .dest_port, .proto, .alert .signature_id, .alert .signature, .alert .category]' | sed 's/^.//g; s/"//g; s/]//g')"

# WhiteList's;
check_list () {
    status_cln="false" ; status_cls="false"
    if grepcidr "${WHITELIST_NETWORKS}" <(echo "${src_ip}") > /dev/null; then status_cln="true" ; fi
    if grep -q -E "(^|\s+)${signature_id}\b" <<< "${WHITELIST_SIGNATURE_ID}"; then status_cls="true" ; fi
}

# Mark IP;
check_ip () {
    status_ci="false"
    check_timestamp="$(awk -v t=$(date -d"-${FW_TIMEOUT} day" +%Y-%m-%dT%H:%M:%S) '$2<t' "${MARK_IP}")"
    for cts in $check_timestamp ; do sed -i "/${cts}/d" "${MARK_IP}" ; done
    if ! grep -q "${src_ip}" "${MARK_IP}"; then status_ci="true" ; echo "${src_ip}, ${timestamp::-12}" >> "${MARK_IP}" ; fi
}

# Check Tmux Session;
check_tmux () {
    if [ "$status_ci" = "true" ]; then
        status_ct="true"
        if ! if_error_ct="$(tmux has-session -t mbi 2>&1)"; then
            status_ct="false"
            logger "[!] [@check_tmux] — [:: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::] — Error - ${if_error_ct}."
            sed -i "/${src_ip}/d" "${MARK_IP}"
            tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}"" &
            # wait for last background process to finish;
            local w_pid="$!" ; wait "$w_pid"
            
        fi
    fi
}

# Ban IP;
mik_ban_ip () {
    # both conditions must be true;
    if [[ "$status_ci" = "true" && "$status_ct" = "true" ]]; then
        #echo ":: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::"
        comment_mbi=":: $dest_ip:$dest_port/$proto :: [$signature_id] :: $signature :: $category ::"
        cmd_mbi='/ip firewall address-list add list="'${FW_LIST}'" address="'${src_ip}'" timeout="'${FW_TIMEOUT}d'" comment="'$comment_mbi'"'
        tmux send-keys -t mbi "${cmd_mbi}" Enter
    fi
}

IFS=$'\n'
for alert in $alerts; do
    IFS="," read -r timestamp src_ip dest_ip dest_port proto signature_id signature category <<< "$alert"
    # one of the conditions must be true;
    check_list ; if [[ "$status_cln" = "true" || "$status_cls" = "true" ]] ; then continue ; fi
    check_ip
    check_tmux
    mik_ban_ip
done

done
