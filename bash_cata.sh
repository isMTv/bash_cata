#!/usr/bin/env bash
#
# bash_cata v1.0;
#
# required packages: jq, grepcidr, tmux;
#
# Bashcata Variables;
ROUTER="" # mikrotik ip;
LOGIN="idps" # user for connect to mikrotik;
PRIVATEKEY="/root/.ssh/idps_ed25519" # private key for ssh;
FW_LIST="idps_alert" # name firewall list;
FW_TIMEOUT="28" # days ban ip;
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
RSC_LIST="${SCRIPT_DIR}/${FW_LIST}.rsc"
# - #

# Initialization TMUX session;
# only in this order (tmux, sleep);
if ! tmux has-session -t bash_cata &> /dev/null; then
    tmux new-session -d -s bash_cata "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}""
    sleep 3
fi

# Check files;
[ -e "${MARK_IP}" ] || touch "${MARK_IP}"

# Setting the logger utility function;
function logger () {
    find "${SCRIPT_DIR:?}"/ -maxdepth 1 -name "*.log" -size +100k -exec rm -f {} \;
    echo -e "[$(date "+%d.%m.%Y / %H:%M:%S")]: $1" >> "${SCRIPT_DIR}"/"${0%.sh}.log"
}

# Purge Mark IP on Timestamp;
purge_mark_ip () {
    IFS=$'\n'
    for purge_mark_ip_timestamp in $(awk -v t=$(date -d"-${FW_TIMEOUT} day" +%Y-%m-%dT%H:%M:%S) '$2<t' "${MARK_IP}"); do
        sed -i "/${purge_mark_ip_timestamp%%,*}/d" "${MARK_IP}"
    done
}

# Restore Address List;
restore_address_list () {
    [ "$FW_LIST_RESTORE" = "true" ] &&
    if [ -e "$MIK_ON" ]; then
        purge_mark_ip
        echo "/ip/firewall/address-list/" > "${RSC_LIST}"
        time_zone="$(date +%z)"; sec_cur_date="$(date -d"${time_zone::+3}hour +${time_zone:3}min" +%s)"
        IFS=$'\n'
        # days left from MARK_IP;
        for restore_mark_ip in $(< $MARK_IP); do
            IFS="," read -r r_src_ip r_timestamp r_comment_list <<< "$restore_mark_ip"
            sec_timestamp="$(date -d"$r_timestamp" +%s)"
            sec_work="$(( $sec_cur_date - $sec_timestamp ))"
            sec_left="$(( $FW_TIMEOUT * 86400 - $sec_work ))"
            days_left="$(date -d "@$sec_left" "+$(($sec_left/86400))d%H:%M:%S")"
            cmd_rsc_list='add list="'${FW_LIST}'" address="'${r_src_ip}'" timeout="'${days_left}'" comment="'${r_comment_list#* }'"'
            echo "${cmd_rsc_list}" >> "${RSC_LIST}"
        done
        # import rsc file in mik;
        if if_error_scp="$(scp -i "${PRIV_KEY}" -o ConnectTimeout=3 "${RSC_LIST}" "${LOGIN}"@"${ROUTER}":"/ram-disk" 2>&1)"; then
            cmd_import_rsc_list='/import ram-disk/'${FW_LIST}'.rsc ; /file/remove ram-disk/'${FW_LIST}'.rsc'
            sleep 3 ; tmux send-keys -t bash_cata "${cmd_import_rsc_list}" Enter
            [ -e "$MIK_ON" ] && rm "${MIK_ON:?}"
        else
            logger "[!] [@restore_address_list] — [:: scp ::] — Error - ${if_error_scp}."
        fi
    fi
}

# WhiteList's;
white_list () {
    # white ip's;
    if grepcidr "${WHITELIST_NETWORKS}" <(echo "${src_ip}") > /dev/null; then
        white_list_net="true"
    else
        white_list_net="false"
    fi
    # white sig's;
    if grep -q -E "(^|\s+)${signature_id}\b" <<< "${WHITELIST_SIGNATURE_ID}"; then
        white_list_sig="true"
    else
        white_list_sig="false"
    fi
}

# Mark IP;
mark_ip () {
    if ! grep -q "${src_ip}" "${MARK_IP}"; then
        mark_ip_new="true"
        mark_ip_comment=":: $dest_ip:$dest_port/$proto :: [$signature_id] :: $signature :: $category ::"
        echo "${src_ip}, ${timestamp::-12}, ${mark_ip_comment}" >> "${MARK_IP}"
    else
        mark_ip_new="false"
    fi
}

# Check Tmux Session;
check_tmux () {
    if [ "$mark_ip_new" = "true" ]; then
        if ! if_error_check_tmux="$(tmux has-session -t bash_cata 2>&1)"; then
            check_tmux_session="false"
            logger "[!] [@check_tmux] — [:: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::] — Error - ${if_error_check_tmux}."
            sed -i "/${src_ip}/d" "${MARK_IP}"
            # only in this order (tmux, sleep);
            if ! tmux has-session -t bash_cata &> /dev/null; then
                tmux new-session -d -s bash_cata "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${LOGIN}"@"${ROUTER}" -i "${PRIVATEKEY}""
                sleep 60
            fi
        else
            check_tmux_session="true"
        fi
    fi
}

# Mik Ban IP;
mik_ban_ip () {
    # both conditions must be true;
    if [[ "$mark_ip_new" = "true" && "$check_tmux_session" = "true" ]]; then
        #echo ":: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::"
        cmd_mik_ban_ip='/ip/firewall/address-list/add list="'${FW_LIST}'" address="'${src_ip}'" timeout="'${FW_TIMEOUT}d'" comment="'${mark_ip_comment}'"'
        sleep 0.1 ; tmux send-keys -t bash_cata "${cmd_mik_ban_ip}" Enter
    fi
}

# Tail Conveyor;
tail_conveyor () {
    tail -q -f "${ALERTS_FILE}" --pid="$PID_SURICATA" -n 500 | while read -r LINE; do
        # Parsing Json file via jq;
        alerts="$(echo "${LINE}" | jq -c '[.timestamp, .src_ip, .dest_ip, .dest_port, .proto, .alert .signature_id, .alert .signature, .alert .category]' | sed 's/^.//g; s/"//g; s/]//g')"
        IFS=$'\n'
        for alert in $alerts; do
            IFS="," read -r timestamp src_ip dest_ip dest_port proto signature_id signature category <<< "$alert"
            purge_mark_ip
            # one of the conditions must be true;
            white_list ; [[ "$white_list_net" = "true" || "$white_list_sig" = "true" ]] && continue
            mark_ip
            check_tmux
            mik_ban_ip
        done
    done
}

# Script Initialization;
main () {
    restore_address_list
    tail_conveyor
}

# Running Script;
main
