# LibreNMS Openvpn stats
This is a simple script heavily inspired by librenms's wireguard.py data collection script via SNMP: https://github.com/librenms/librenms-agent/blob/master/snmp/wireguard.py and https://github.com/hjelev/OpenVPN-Stats/blob/master/openvpn_stats.py for use with librenms wireguard monitoring

it mimics wireguard.py behaviour, enabling stats collection in librenms using wireguard app. It collects client name, traffic, and last handshake time for all clients on tun0 interface. The data then appears in librenms as if it was a wireguard app

## Prerequisites
- A working LibreNMS installation, either standard or containerized.
- An openvpn server, with status log enabled
- snmpd package installed on openvpn host

## Installation
1. Clone repo
2. Copy this script to (for example) /opt/openvpn-snmp-stats and make it executable:
```
chmod +x /opt/openvpn-snmp-stats/openvpn.py
```
3. Create the required logs storage dir: 
```
mkdir /opt/openvpn-snmp-stats/db
```
4. Give sudo rights to Debian-snmp user for this script: 
```
visudo /etc/sudoers.d/openvpn-stats
```
Note: Debian-snmp is the default user running snmpd service on debian hosts
```
Debian-snmp ALL = NOPASSWD: /opt/openvpn-snmp-stats/openvpn.py
```
5. Edit your snmpd.conf and include:
```
view   systemonly  included   .1.3.6.1.4.1.8072.1.3.2
extend wireguard /usr/bin/sudo /opt/openvpn-snmp-stats/openvpn.py
```
6. Restart snmpd
```
systemctl restart snmpd.service
```
7. activate wireguard app (in ilbrenms GUI) for desired host.
## Roadmap
to be defined
