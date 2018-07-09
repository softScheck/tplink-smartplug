#!/usr/bin/env python2
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016-2018 softScheck GmbH
# Copyrifht 2018 Wojciech Owczarek
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

from socket import *
from struct import pack
import argparse
import sys

version = 0.3

# Check if hostname is valid
def validHostname(hostname):
	try:
		gethostbyname(hostname)
	except error:
		parser.error("Invalid hostname.")
	return hostname

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
	if args.broadcast or args.udp:
	    result = ""
	else:
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

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", metavar="<hostname>", help="Target hostname or IP address", type=validHostname)
group.add_argument("-b", "--broadcast", help="Send UDP broadcast (255.255.255.255)", default=False, action='store_true')

group = parser.add_mutually_exclusive_group()
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")

parser.add_argument("-u", "--udp", help="Send command via UDP instead of TCP (broadcast always UDP)", default=False, action='store_true')
parser.add_argument("-s", "--source", metavar="<address>", help="Source IP address to use (default is any source)", default="0.0.0.0", type=validHostname)
parser.add_argument("-T", "--timeout", metavar="<seconds>", help="Maximum time to wait for broadcast reply", default="0.5", type=float, choices=range(0, 3600))

args = parser.parse_args()


# Set target IP, port and command to send
bufsize = 2048
ip = args.target
listenport = 9999
port = 9999
headerlen = 4

if args.command is None:
	cmd = args.json
	if cmd is None:
		cmd = commands['info']
else:
	cmd = commands[args.command]

if args.broadcast:
	ip = "255.255.255.255"
	headerlen = 0
if args.udp:
	headerlen = 0

# Send command and receive reply
try:

	gotdata = False

	if args.broadcast or args.udp:
	    sock = socket(AF_INET, SOCK_DGRAM)
	    sock.bind((args.source, listenport))
	    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	    if args.broadcast:
		sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	    sock.sendto(encrypt(cmd), (ip, port))
	    if args.broadcast:
		sys.stderr.write("Broadcasted:     " + cmd + '\n')
	    else:
		sys.stderr.write("Sent via UDP:     " + cmd + '\n')
	    sock.settimeout(args.timeout)
	    (data, src)  = sock.recvfrom(bufsize)
	    while data is not None:
		gotdata = True
		sys.stderr.write("Received from "+src[0]+":"+str(src[1])+": ")
		print decrypt(data[headerlen:])
		(data, src) = sock.recvfrom(bufsize)
	else:
	    sock = socket(AF_INET, SOCK_STREAM)
	    sock.bind((args.source, listenport))
	    sock.connect((ip, port))
	    sock.send(encrypt(cmd))
	    sys.stderr.write("Sent via TCP:     " + cmd + '\n')
	    data = sock.recv(bufsize)
	    sys.stderr.write("Received: ")
	    print decrypt(data[headerlen:])

	sock.close()

except timeout:
	if gotdata:
	    quit("Timeout (no more data)")
	else:
	    quit("Timeout and no data received while sending to " + ip + ":" + str(port))
except error:
	quit("Cound not connect to host " + ip + ":" + str(port))

