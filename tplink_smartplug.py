#!/usr/bin/env python2
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import socket
import argparse
from struct import pack

version = 0.2

# Check if hostname is valid
def validHostname(hostname):
	try:
		socket.gethostbyname(hostname)
	except socket.error:
		parser.error("Invalid hostname.")
	return hostname

# Check if port is valid
def validPort(port):
        try:
            port = int(port)
        except ValueError:
            parser.error("Invalid port number.")

        if ((port <= 1024) or (port >65535)) :
            parser.error("Invalid port number.")

        return port


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
			'on'       : '{"system":{"set_relay_state":{"state":1}}}',
			'off'      : '{"system":{"set_relay_state":{"state":0}}}',
			'cloudinfo': '{"cnCloud":{"get_info":{}}}',
			'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
			'time'     : '{"time":{"get_time":{}}}',
			'schedule' : '{"schedule":{"get_rules":{}}}',
			'countdown': '{"count_down":{"get_rules":{}}}',
			'antitheft': '{"anti_theft":{"get_rules":{}}}',
			'reboot'   : '{"system":{"reboot":{"delay":1}}}',
			'reset'    : '{"system":{"reset":{"delay":1}}}',
			'energy'   : '{"emeter":{"get_realtime":{}}}'
}

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = pack('>I', len(string))
	for i in string:
		a = key ^ ord(i)
		key = a
		result += chr(a)
	return result

def decrypt(string):
	key = 171
	result = ""
	for i in string:
		a = key ^ ord(i)
		key = ord(i)
		result += chr(a)
	return result

# Parse commandline arguments
parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
parser.add_argument("-t", "--target", metavar="<hostname>", required=True, help="Target hostname or IP address", type=validHostname)
parser.add_argument("-p", "--port", metavar="<port>", default=9999, required=False, help="Target port", type=validPort)
parser.add_argument("-q", "--quiet", dest='quiet', action='store_true', help="Only show result")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
parser.add_argument('--influxdb', type=str, metavar=("URI", "database"), default=None,
		nargs=2, help='If command is "energy", push to influxdb. URI should point to influxdb, e.g. [http/https]://<ip>:<port>. Database: e.g. smarthome.')
parser.add_argument('--influxdb_energy', type=str, metavar="query", default=None,
		help='query to store energy as Joule, e.g. energy,type=elec,device=hs110-1 this will be appended with <energy in joule> (as int)')
parser.add_argument('--influxdb_power', type=str, metavar="query", default=None,
		help='query to store power as Watt, e.g. power,type=elec,device=hs110-1 this will be appended with <power in W> (as float)')
args = parser.parse_args()


# Set target IP, port and command to send
ip = args.target
port = args.port
if args.command is None:
	cmd = args.json
else:
	cmd = commands[args.command]



# Send command and receive reply
try:
	sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_tcp.connect((ip, port))
	sock_tcp.send(encrypt(cmd))
	data = sock_tcp.recv(2048)
	sock_tcp.close()

	decrypted = decrypt(data[4:])

	if args.quiet:
		print decrypted
	else:
		print "Sent:     ", cmd
		print "Received: ", decrypted

except socket.error:
	quit("Cound not connect to host " + ip + ":" + str(port))

if (args.command == "energy") and (args.influxdb != None):
	import requests
	import json

	# Get total_wh and power_mw from json response
	energy_response = decrypt(data[4:])
	energy_wh = json.loads(energy_response)['emeter']['get_realtime']['total_wh']
	energy_joule = int(energy_wh)*3600
	power_mW = json.loads(energy_response)['emeter']['get_realtime']['power_mw']
	power_W = float(power_mW)/1000.0

	# Build URI and query
	# Something like req_url = "http://localhost:8086/write?db=smarthometest&precision=s"
	# Something like post_data = "water,type=usage,device=devicename value=1"
	req_url = args.influxdb[0]+"/write?db="+args.influxdb[1]+"&precision=s"
	post_data = ""
	if (args.influxdb_energy != None):
		post_data = args.influxdb_energy+" value="+str(energy_joule)
	if (args.influxdb_power != None):
		post_data += "\n"+args.influxdb_power+" value="+str(power_W)

	# Post data to influxdb, check for obvious errors
	try:
		httpresponse = requests.post(req_url, data=post_data, verify=False, timeout=5)
		if (httpresponse.status_code != 204):
			print "Push to influxdb failed: " + str(httpresponse.status_code) + " - " + str(httpresponse.text)
	except requests.exceptions.Timeout as e:
		print "Update failed due to timeout. Is influxdb running?"

