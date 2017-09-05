#!/usr/bin/env python
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
#
import socket
import argparse

version = 0.1

# Check if IP is valid
def validIP(ip):
	try:
		socket.inet_pton(socket.AF_INET, ip)
	except socket.error:
		parser.error("Invalid IP Address.")
	return ip 

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
			'reset'    : '{"system":{"reset":{"delay":1}}}'
}

light_commands = {
	'on': '{"smartlife.iot.smartbulb.lightingservice":{"transition_light_state":{"on_off":1,"transition_period":0}}}',
	'off': '{"smartlife.iot.smartbulb.lightingservice":{"transition_light_state":{"on_off":0,"transition_period":0}}}'
}

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string, doHeader=True):
	key = 171
	if doHeader:
		result = "\0\0\0\0"
	else:
		result = ""
	for i in string: 
		a = key ^ ord(i)
		key = a
		result += chr(a)
	return result

def decrypt(string, doHeader=True):
	key = 171 
	result = ""
	if doHeader:
		string = string[4:]
	for i in string: 
		a = key ^ ord(i)
		key = ord(i) 
		result += chr(a)
	return result

# Parse commandline arguments
parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
parser.add_argument("-t", "--target", metavar="<ip>", required=True, help="Target IP Address", type=validIP)
parser.add_argument("-l", "--lightbulb", dest="lightbulb", help="Enable lightbulb mode", action="store_true")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands) 
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
args = parser.parse_args()

# Set target IP, port and command to send
ip = args.target
port = 9999
if args.command is None:
	cmd = args.json
else:
	if args.lightbulb:
		cmd = light_commands[args.command]
	else:
		cmd = commands[args.command]

# Send command and receive reply 
try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if args.lightbulb else socket.SOCK_STREAM)
	sock.settimeout(1)
	sock.sendto(encrypt(cmd, not args.lightbulb), (ip, port))
	data = decrypt(sock.recv(2048), not args.lightbulb)
	sock.close()
	
	print "Sent:     ", cmd
	print "Received: ", data
except socket.error:
	quit("Cound not connect to host " + ip + ":" + str(port))
