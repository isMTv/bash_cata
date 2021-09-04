#!/usr/bin/env bash
#
# required packages: jq, grepcidr, tmux;
#
# Bashcata Variables;
router="" # mikrotik ip;
login="" # user for connect to mikrotik;
privatekey="/root/.ssh/mik_rsa" # private key for ssh;
fw_list="idps_alert" # name firewall list;
fw_timeout="7" # days ban ip;
whitelist_networks="" # networks: a.b.c.d/xy, a.b.c.d-e.f.g.h, a.b.c.d;
whitelist_signature_id="" # suricata signature_id: through a space;

# - #
script_dir="$(dirname "$(readlink -f "$0")")"
alerts_file="/var/log/suricata/alerts.json"
pid_suricata="$(pidof suricata)"
mark_ip="${script_dir}/mark.ip"
# - #

# Initialization TMUX session;
if ! tmux has-session -t mbi &> /dev/null; then
    tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${login}"@"${router}" -i "${privatekey}"" ; sleep 3s
fi

# Check files;
if [ ! -e "${mark_ip}" ]; then touch "${mark_ip}" ; fi

# Setting the logger utility function;
function logger() {
    find "${script_dir}"/ -maxdepth 1 -name "*.log" -size +100k -exec rm -f {} \;
    echo -e "[$(date "+%d.%m.%Y / %H:%M:%S")]: $1" >> "${script_dir}"/"bash_cata.log"
}

# Tail Conveyor;
tail -q -f "${alerts_file}" --pid="$pid_suricata" -n 500 | while read -r LINE; do

# Parsing Json file via jq;
alerts="$(echo "${LINE}" | jq -c '[.timestamp, .src_ip, .dest_ip, .dest_port, .proto, .alert .signature_id, .alert .signature, .alert .category]' | sed 's/^.//g; s/"//g; s/]//g')"

# WhiteList's;
check_list () {
    status_cln="false" ; status_cls="false"
    if grepcidr "${whitelist_networks}" <(echo "${src_ip}") > /dev/null; then status_cln="true" ; fi
    if grep -q -E "(^|\s+)${signature_id}\b" <<< "${whitelist_signature_id}"; then status_cls="true" ; fi
}

# Mark IP;
check_ip () {
    status_ci="false"
    check_timestamp="$(awk -v t=$(date -d"-${fw_timeout} day" +%Y-%m-%dT%H:%M:%S) '$2<t' "${mark_ip}")"
    for cts in $check_timestamp ; do sed -i "/${cts}/d" "${mark_ip}" ; done
    if ! grep -q "${src_ip}" "${mark_ip}"; then status_ci="true" ; echo "${src_ip}, ${timestamp::-12}" >> "${mark_ip}" ; fi
}

# Check Tmux Session;
check_tmux () {
    if [ "$status_ci" = "true" ]; then
        status_ct="true"
        if ! if_error_ct="$(tmux has-session -t mbi 2>&1)"; then
            status_ct="false"
            logger "[!] [@check_tmux] — [:: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::] — Error - ${if_error_ct}."
            sed -i "/${src_ip}/d" "${mark_ip}"
            tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${login}"@"${router}" -i "${privatekey}"" ; sleep 3s
        fi
    fi
}

# Ban IP;
mik_ban_ip () {
    # both conditions must be true;
    if [[ "$status_ci" = "true" && "$status_ct" = "true" ]]; then
        #echo ":: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::"
        comment_mbi=":: $dest_ip:$dest_port/$proto :: [$signature_id] :: $signature :: $category ::"
        cmd_mbi='/ip firewall address-list add list="'${fw_list}'" address="'${src_ip}'" timeout="'${fw_timeout}d'" comment="'$comment_mbi'"'
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
