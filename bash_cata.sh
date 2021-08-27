#!/usr/bin/env bash

# Bashcata Variables;
router="" # mikrotik ip;
login="" # user for connect to mikrotik;
privatekey="/root/.ssh/mik_rsa" # private key for ssh;
fw_list="idps_alert" # name firewall list;
fw_timeout="7" # days ban ip;
wl_netmask="3" # whitelist net mask, only 4=/32, 3=/24, 2=/16, 1=/8;

# - #
script_dir="$(dirname "$(readlink -f "$0")")"
alerts_file="/var/log/suricata/alerts.json"
pid_suricata="$(pidof suricata)"
white_list="${script_dir}/white.list"
mark_ip="${script_dir}/mark.ip"
# - #

# Initialization TMUX session;
if ! tmux has-session -t mbi &> /dev/null; then
    tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${login}"@"${router}" -i "${privatekey}"" ; sleep 3s
fi

# Check files;
if [ ! -e "${white_list}" ]; then touch "${white_list}" ; echo -e "# net_address/mask\n\n# signature_id" > "${white_list}" ; fi
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

# White List;
check_list () {
    wl="false"
    src_ip_mask="$(cut -d. -f1-$wl_netmask <<< "$src_ip")"
    if grep -q -E "${src_ip_mask}|${signature_id}" "${white_list}"; then wl="true" ; fi
}

# Mark IP;
check_ip () {
    new_ip="false"
    check_timestamp="$(awk -v t=$(date -d"-${fw_timeout} day" +%Y-%m-%dT%H:%M:%S) '$2<t' "${mark_ip}")"
    for cts in $check_timestamp ; do sed -i "/${cts}/d" "${mark_ip}" ; done
    if ! grep -q "${src_ip}" "${mark_ip}"; then new_ip="true" ; echo "${src_ip}, ${timestamp::-12}" >> "${mark_ip}" ; fi
}

# Check Tmux Session;
check_tmux () {
    if [ "$new_ip" = "true" ]; then
        ct="true"
        if ! else_error_ct="$(tmux has-session -t mbi 2>&1)"; then
            ct="false"
            logger "[!] [@check_tmux] — [:: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::] — Error - ${else_error_ct}."
            sed -i "/${src_ip}/d" "${mark_ip}"
            tmux new-session -d -s mbi "ssh -o ConnectTimeout=3 -o ServerAliveInterval=900 "${login}"@"${router}" -i "${privatekey}"" ; sleep 3s
        fi
    fi
}

# Ban IP;
mik_ban_ip () {
    if [[ "$new_ip" = "true" && "$ct" = "true" ]]; then
        #echo ":: $src_ip :: $dest_ip:$dest_port/$proto :: $signature_id ::"
        comment_mbi=":: $dest_ip:$dest_port/$proto :: [$signature_id] :: $signature :: $category ::"
        cmd_mbi='/ip firewall address-list add list="'${fw_list}'" address="'${src_ip}'" timeout="'${fw_timeout}d'" comment="'$comment_mbi'"'
        tmux send-keys -t mbi "${cmd_mbi}" Enter
    fi
}

IFS=$'\n'
for alert in $alerts; do
    IFS="," read -r timestamp src_ip dest_ip dest_port proto signature_id signature category <<< "$alert"
    check_list ; if [ "$wl" = "true" ] ; then continue ; fi
    check_ip
    check_tmux
    mik_ban_ip
done

done
