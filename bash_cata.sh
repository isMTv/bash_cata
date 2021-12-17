#!/usr/bin/env bash
#
# required packages: jq, grepcidr, tmux;
#
# Bashcata Variables;
ROUTER="" # mikrotik ip;
LOGIN="idps" # user for connect to mikrotik;
PRIVATEKEY="/root/.ssh/mik_rsa" # private key for ssh;
FW_LIST="idps_alert" # name firewall list;
FW_TIMEOUT="7" # days ban ip;
FW_LIST_RESTORE="false" # restore address list after router reboot;
WHITELIST_NETWORKS="1.1.1.1 1.1.1.2 \
2.2.2.0/19 3.3.3.0/29 \
4.4.4.4-4.4.5.5" # networks: a.b.c.d/xy, a.b.c.d-e.f.g.h, a.b.c.d;
WHITELIST_SIGNATURE_ID="" # suricata signature_id: through a space;

# - #
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
ALERTS_FILE="/var/log/suricata/alerts.json"
PID_SURICATA="$(pidof suricata)"
MARK_IP="${SCRIPT_DIR}/mark.ip"
MIK_ON="${SCRIPT_DIR}/mik.on"
# - #

# Initialization TMUX session;
if ! tmux has-session -t bash_cata &> /dev/null; then
    tmux new-session -d -s bash_cata "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}"" &
    # wait for last background process to finish;
    w_pid="$!" ; wait "$w_pid"
fi

# Check files;
[ -e "${MARK_IP}" ] || touch "${MARK_IP}"

# Setting the logger utility function;
function logger() {
    find "${SCRIPT_DIR:?}"/ -maxdepth 1 -name "*.log" -size +100k -exec rm -f {} \;
    echo -e "[$(date "+%d.%m.%Y / %H:%M:%S")]: $1" >> "${SCRIPT_DIR}"/"bash_cata.log"
}

# WhiteList's;
check_list () {
    status_check_list_net="false" ; status_check_list_sig="false"
    if grepcidr "${WHITELIST_NETWORKS}" <(echo "${src_ip}") > /dev/null; then status_check_list_net="true" ; fi
    if grep -q -E "(^|\s+)${signature_id}\b" <<< "${WHITELIST_SIGNATURE_ID}"; then status_check_list_sig="true" ; fi
}

# Mark IP;
check_ip () {
    status_check_ip="false"
    check_timestamp="$(awk -v t=$(date -d"-${FW_TIMEOUT} day" +%Y-%m-%dT%H:%M:%S) '$2<t' "${MARK_IP}")"
    for cts in $check_timestamp ; do sed -i "/${cts}/d" "${MARK_IP}" ; done
    if ! grep -q "${src_ip}" "${MARK_IP}"; then
        status_check_ip="true"
        comment_list=":: $dest_ip:$dest_port/$proto :: [$signature_id] :: $signature :: $category ::"
        echo "${src_ip}, ${timestamp::-12}, ${comment_list}" >> "${MARK_IP}"
    fi
}

# Check Tmux Session;
check_tmux () {
    if [ "$status_check_ip" = "true" ]; then
        status_check_tmux="true"
        if ! if_error_check_tmux="$(tmux has-session -t bash_cata 2>&1)"; then
            status_check_tmux="false"
            logger "[!] [@check_tmux] — [:: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::] — Error - ${if_error_check_tmux}."
            sed -i "/${src_ip}/d" "${MARK_IP}"
            tmux new-session -d -s bash_cata "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}""
            sleep 2
        fi
    fi
}

# Ban IP;
mik_ban_ip () {
    # both conditions must be true;
    if [[ "$status_check_ip" = "true" && "$status_check_tmux" = "true" ]]; then
        #echo ":: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::"
        cmd_mik_ban_ip='/ip firewall address-list add list="'${FW_LIST}'" address="'${src_ip}'" timeout="'${FW_TIMEOUT}d'" comment="'$comment_list'"'
        tmux send-keys -t bash_cata "${cmd_mik_ban_ip}" Enter
    fi
}

# Restore Address List;
restore_address_list () {
    [ "$FW_LIST_RESTORE" = "true" ] &&
    # both conditions must be true;
    if [[ -e "$MIK_ON" && "tmux has-session -t bash_cata" ]]; then
        time_zone="$(date +%z)"; sec_cur_date="$(date -d"${time_zone::+3}hour +${time_zone:3}min" +%s)"
        get_mark_ip="$(cat $MARK_IP)" ; IFS=$'\n'
        for mark_ip in $get_mark_ip; do
            IFS="," read -r r_src_ip r_timestamp r_comment_list <<< "$mark_ip"
            sec_timestamp="$(date -d"$r_timestamp" +%s)"
            sec_work="$(( $sec_cur_date - $sec_timestamp ))"
            sec_left="$(( $FW_TIMEOUT * 86400 - $sec_work ))"
            days_left="$(date -d "@$sec_left" "+$(($sec_left/86400))d%H:%M:%S")"
            cmd_restore_list='/ip firewall address-list add list="'${FW_LIST}'" address="'${r_src_ip}'" timeout="'${days_left}'" comment="'${r_comment_list#* }'"'
            tmux send-keys -t bash_cata "${cmd_restore_list}" Enter
        done
        [ -e "$MIK_ON" ] && rm "${MIK_ON:?}"
    fi
}

# Tail Conveyor;
tail -q -f "${ALERTS_FILE}" --pid="$PID_SURICATA" -n 500 | while read -r LINE; do
    # Parsing Json file via jq;
    alerts="$(echo "${LINE}" | jq -c '[.timestamp, .src_ip, .dest_ip, .dest_port, .proto, .alert .signature_id, .alert .signature, .alert .category]' | sed 's/^.//g; s/"//g; s/]//g')"
    IFS=$'\n'
    for alert in $alerts; do
        IFS="," read -r timestamp src_ip dest_ip dest_port proto signature_id signature category <<< "$alert"
        # one of the conditions must be true;
        check_list ; if [[ "$status_check_list_net" = "true" || "$status_check_list_sig" = "true" ]] ; then continue ; fi
        check_ip
        check_tmux
        mik_ban_ip
        restore_address_list
    done
done
