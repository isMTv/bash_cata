## Overview:
A simple script that processes the generated Suricata eve-log in real time and, based on alerts, adds an ip-address to the MikroTik Address Lists for a specified time for subsequent blocking;
* Connects to MikroTik using ssh-key.
* Cli commands are sent directly to the mikrotik terminal in the established session which does not close;
* Works as a daemon with attachment to the Suricata process;
* There is a whitelist to which "networks" and "signature_id" can be added;
* Marks blocked ip-addresses in the "mark_ip" file and automatically clears the file as the timestamp expires;
* Possebility restore address list after router reboot;
* In case of errors when connecting to MikroTik, add them to "bash_cata.log".

## For work you need:
* ./jq (https://stedolan.github.io/jq/)
* grepcidr (http://www.pc-tools.net/unix/grepcidr/)
* tmux (https://github.com/tmux/tmux/wiki)
* tzsp2pcap (https://github.com/thefloweringash/tzsp2pcap)
* tcpreplay (https://github.com/appneta/tcpreplay)

## How-to:
### IMPORTANT: In suricata.yaml add another eve-log:
```
- eve-log:
      enabled: yes
      filetype: regular
      filename: alerts.json
      types:
        - alert
```

### Configuring ssh key authorization:
```
Create key mik_rsa:
# cd ~/.ssh/
# ssh-keygen -t rsa -b 2048
- /root/.ssh/mik_rsa
id_rsa [mik_rsa] - secret key (for the host from which we are connecting)
id_rsa.pub [mik_rsa.pub] - public key (for the host to which we are connecting)
```

### We specify a lot of hosts through a space:
```
# nano ~/.ssh/config
Host 172.16.5.89
IdentityFile ~/.ssh/mik_rsa
#ConnectTimeout 3
#ServerAliveInterval 900

# chmod 600 ~/.ssh/config
# service sshd restart
```

### Copy script directory to:
```
# "/home/shells/"
# cd /home/shells/bash_cata/ ; chmod +x bash_cata.sh
```

### Setting up the daemon:
```
# cp bashcata.service /etc/systemd/system/
# systemctl daemon-reload
# systemctl enable bashcata.service
# systemctl start bashcata.service
# systemctl status bashcata.service
```

### Logrotate: option required "copytruncate"
cp suricata /etc/logrotate.d/
```
# Sample /etc/logrotate.d/suricata configuration file.
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    missingok
    rotate 3
    compress
    delaycompress
    copytruncate
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /run/suricata.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
```

### snif TZSP:
cp tzsp.netdev /etc/systemd/network/
```
[NetDev]
Name=tzsp0
Kind=dummy
```

cp tzsp.network /etc/systemd/network/
```
[Match]
Name=tzsp*

[Link]
MTUBytes=2000

[Network]
Address=172.17.1.1/24
DHCP=no
```

Enable interface:
```
# systemctl enable systemd-networkd
# systemctl restart systemd-networkd
```

Combine tzsp2pcap and tcpreplay into TZSPreplay@.service:

cp TZSPreplay@.service /etc/systemd/system/
```
[Unit]
Description=TZSP Replay on dev %i
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=/bin/sh -c "/usr/bin/tzsp2pcap -f | /usr/bin/tcpreplay-edit --topspeed --mtu=$(cat /sys/class/net/%I/mtu) --mtu-trunc -i %I -"
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Start it on your dummy interface (I'm using name tzsp0, you can have dummy0 or whatever):
```
# systemctl enable --now TZSPreplay@tzsp0.service
```

/etc/suricata/suricata.yaml:
```
af-packet:
  - interface: tzsp0
```

### ROS:
In the "prerouting" chain we direct traffic to Suricata's ip-address. We can specify any interface and chain, as well as create the required number of rules with the action sniff TZSP.
```
 - Create Interface List:
/interface list
add name=IDPS comment="Intrusion detection/prevention system"
 - Add interfaces to the list:
/interface list member
add interface=bonding1.56 list=IDPS
add interface=bonding1.64 list=IDPS
 - Add rules TSZP Sniff:
/ip firewall mangle
add chain=forward in-interface-list=ISP out-interface-list=IDPS action=sniff-tzsp sniff-target=ip-address-suricata sniff-target-port=37008 comment="TZSP sniffing -> IDPS"
add chain=forward in-interface-list=IDPS out-interface-list=ISP action=sniff-tzsp sniff-target=ip-address-suricata sniff-target-port=37008
 - Block ip-address's from idps_alert table:
/ip firewall raw
add chain=prerouting src-address-list=idps_alert action=drop comment="Drop IDPS"
```

### Secure SSH:
```
/ip ssh set strong-crypto=yes
/ip ssh set always-allow-password-login=no
```

### Restore Adress List:
SSH-exec configuration required. https://wiki.mikrotik.com/wiki/Manual:System/SSH_client#SSH-exec
* /.../.../bash_cata/mik.on - replace with the path where the bash_cata script is located;
* delay 25 - the time that the router will spend to turn it on completely;
* local ip - ip address host on which the script is running;
```
/system script add name="bash_cata" policy="ftp,read,write,test"
---
:delay 25;
:local ip "ip_bash_cata_script
:if ([/ping address=$ip count=3] = 0) do={
    /log warning message="bash_cata: host $ip - unavalable";
    /system scheduler set bash_cata interval="00:04:35";
} else={
    /log warning message="bash_cata: host $ip - available";
    /system scheduler set bash_cata interval="00:00:00";
    /system ssh-exec address="$ip" port=22 user=root command="touch /.../.../bash_cata/mik.on ; systemctl restart bashcata.service";
}
---
/system scheduler add name="bash_cata" start-time=startup interval="00:00:00" policy="ftp,read,write,test" on-event="/system script run bash_cata"
---
### Сreating a key pair in linux host::
# mkdir mik_exec && ssh-keygen -t rsa -b 2048 -m pem
```

### Thanks for the Idea:
* zzbe - https://github.com/zzbe/mikrocata
