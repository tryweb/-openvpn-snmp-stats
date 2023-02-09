#!/usr/bin/env python
#
# Name: Openvpn Script
# Author: Thierry Diaz <thierry.diaz@gmail.com>
# Version: 1.0
# Description: This is a simple script heavily inspired by librenms's wireguard.py data collection script via SNMP
#              https://github.com/librenms/librenms-agent/blob/master/snmp/wireguard.py
#              and https://github.com/hjelev/OpenVPN-Stats/blob/master/openvpn_stats.py 
#              for use with librenms wireguard monitoring
#              it mimics wireguard.py behaviour, enabling stats collection in librenms using wireguard app
#              It collects client name, traffic, and last handshake time for all clients on tun0 interfaces.
#              The data then appears in librenms as if it was a wireguard app
#
# Installation:
#     1. Copy this script to (for example) /opt/openvpn-snmp-stats and make it executable:
#         chmod +x /opt/openvpn-snmp-stats/openvpn.py
#
#     2. Create the required logs storage dir: mkdir /opt/openvpn-snmp-stats/db
#
#     3. Give sudo rights to Debian-snmp user for this script: 
#        visudo /etc/sudoers.d/openvpn-stats
#        Debian-snmp ALL = NOPASSWD: /opt/openvpn-snmp-stats/openvpn.py
#
#     4. Edit your snmpd.conf and include:
#         view   systemonly  included   .1.3.6.1.4.1.8072.1.3.2
#         extend wireguard /usr/bin/sudo /opt/openvpn-snmp-stats/openvpn.py
#
#     5. Restart snmpd and activate the app for desired host.


import json, sys, os, pickle
from datetime import datetime

LOG_FILE = "/var/log/openvpn/openvpn-status.log"
DB_FOLDER = "db"
INTERFACE = "tun0"

def error_handler(error_name, err):
    """
    error_handler(): Common error handler for config/output parsing and command execution.  We set
                     the data to none and print out the json.
    Inputs:
        error_name: String describing the error handled.
        err: The error message in its entirety.
    Outputs:
        None
    """
    output_data = {
        "errorString": "%s: '%s'" % (error_name, err),
        "error": 1,
        "version": 1,
        "data": {},
    }
    print(json.dumps(output_data))
    sys.exit(1)

def read_stats():
    """
	headers = {  
		'cn':    'Common Name', 
		'virt':  'Virtual Address', 
		'real':  'Real Address', 
		'sent':  'Sent', 
		'recv':  'Received', 
		'since': 'Connected Since'
	}
    """
    try:
        hosts = []

        with open(LOG_FILE, 'r') as status_file:
            stats = status_file.readlines()  

            for line in stats:  
                cols = line.split(',')

                if len(cols) == 5 and not line.startswith('Common Name'):
                    host  = {}
                    host['cn']    = cols[0]
                    host['real']  = cols[1].split(':')[0]
                    host['recv']  = int(cols[2])
                    host['sent']  = int(cols[3])
                    host['since'] = cols[4].strip()
                    hosts.append(host)

                if len(cols) == 4 and not line.startswith('Virtual Address'):
                    for h in hosts:
                        if h['cn'] == cols[1]:
                            h['virt'] = cols[0]
    except (
        IOError,
        KeyError,
        PermissionError,
        OSError,
        json.decoder.JSONDecodeError,
    ) as err:
        error_handler("Config File Error", err)

    return hosts

def getScriptPath(): 
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def update_log(cn,vhost):
	dhosts = []
	fn = os.path.join(getScriptPath(), DB_FOLDER, cn) + ".log"
	if os.path.exists(fn):	
		old_host = pickle.load(open( fn, "rb" )) #read data from file
		
		if old_host[1]['since'] == vhost['since']:	
			dhosts.append(old_host[0])
			dhosts.append(vhost)
		else:
			old_host[0]['recv'] += old_host[1]['recv']
			old_host[0]['sent'] += old_host[1]['sent']
			old_host[0]['since'] = old_host[1]['since']
			old_host[0]['real'] = old_host[1]['real']
			dhosts.append(old_host[0])
			dhosts.append(vhost)
						
		pickle.dump(dhosts, open( fn, "wb" )) # save data to file
	else:
		dhosts.append(vhost)
		dhosts.append(vhost)
		pickle.dump(dhosts, open( fn, "wb" ))
	
	return

def log_parser(file):
    """
    Outputs:
        wireguard_data: A dictionary of a peer's public IP, bytes sent and received, and minutes
                        since last seen.
    """
    try:
        data = pickle.load(open( file, "rb" ))[1]

        friendly_name = data['cn']
        timestamp = data['since']
        bytes_rcvd = int(data['recv'])
        bytes_sent = int(data['sent'])

    except (IndexError, ValueError) as err:
        error_handler("Command Output Parsing Error", err)

    # Calculate minutes since last handshake here datetime.now() - datetime.strptime(timestamp,'%a %b %d %H:%M:%S %Y')
    last_handshake_timestamp = datetime.strptime(timestamp,'%a %b %d %H:%M:%S %Y') if timestamp else 0
    minutes_since_last_handshake = (
        int((datetime.now() - last_handshake_timestamp).total_seconds() / 60)
        if last_handshake_timestamp
        else None
    )
    openvpn_data = {
        friendly_name: {
            "minutes_since_last_handshake": minutes_since_last_handshake,
            "bytes_rcvd": bytes_rcvd,
            "bytes_sent": bytes_sent,
        }
    }
    return openvpn_data

def main():
    """
    main(): main function that delegates config file parsing, and unit stdout
            parsing.  Then it prints out the expected json output for the wireguard application.

    Inputs:
        None
    Outputs:
        None
    """

    output_data = {"errorString": "", "error": 0, "version": 1, "data": {}}
    output_data["data"][INTERFACE] = {}

    # Parse current connections.
    current_clients = read_stats()

    # update stored logs
    for h in current_clients:
        update_log(h['cn'],h)

    # prepare output
    directory = os.path.join(getScriptPath(), DB_FOLDER)
    try:
        for filename in os.listdir(directory):
            file = os.path.join(directory, filename)
            # checking if it is a file
            if os.path.isfile(file):
                for friendly_name, client_data in log_parser(file).items():
                    output_data["data"][INTERFACE][friendly_name] = client_data

    except Exception as err:
        error_handler("Data concatenation", err)

    print(json.dumps(output_data))

if __name__ == "__main__":
    main()
