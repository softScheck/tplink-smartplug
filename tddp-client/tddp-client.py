#!/usr/bin/env python
#
# TP-Link Device Debug Protocol (TDDP) v2 Client
# Based on https://www.google.com/patents/CN102096654A?cl=en
#
# HIGHLY EXPERIMENTAL and untested!
# The protocol is available on all kinds of TP-Link devices such as routers, cameras, smart plugs etc.
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

from pyDes import *
import hashlib
import argparse
import socket
import struct
import binascii
import string

version = 0.2

# Default username and password
username = "admin"
password = "admin"

# Check if IP is valid
def validIP(ip):
	try:
		socket.inet_pton(socket.AF_INET, ip)
	except socket.error:
		parser.error("Invalid IP Address.")
	return ip

# Check if command is two hex chars
def validHex(cmd):
	ishex = all(c in string.hexdigits for c in cmd)
	if len(cmd) == 2 and ishex:
		return cmd
	else:
		parser.error("Please issue a two-character hex command, e.g. 0A")

# Parse commandline arguments
parser = argparse.ArgumentParser(description="Experimental TP-Link TDDPv2 Client v" + str(version))
parser.add_argument("-v", "--verbose", help="Verbose mode", action="store_true")
parser.add_argument("-t", "--target", metavar="<ip>", required=True, help="Target IP Address", type=validIP)
parser.add_argument("-u", "--username", metavar="<username>", help="Username (default: admin)")
parser.add_argument("-p", "--password", metavar="<password>", help="Password (default: admin)")
parser.add_argument("-c", "--command", metavar="<hex>", required=True, help="Command value to send as hex (e.g. 0A)", type=validHex)
args = parser.parse_args()

# Set Target IP, username and password to calculate DES decryption key for data and command to execute
ip = args.target
cmd = args.command
if args.username:
	username = args.username
if args.password:
	password = args.password

# TDDP runs on UDP Port 1040
# Response is sent to UDP Port 61000
port_send = 1040
port_receive = 61000


# TDDP DES Key = MD5 of username and password concatenated
# Key is first 8 bytes only
tddp_key = hashlib.md5(username + password).hexdigest()[:16]
if args.verbose:
	print "TDDP Key:\t", tddp_key, "(" + username + password + ")"

##  TDDP Header
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Ver      |     Type      |     Code     |   ReplyInfo     |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          PktLength                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |             PktID            |    SubType   |     Reserve     |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        MD5 Digest[0-3]                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        MD5 Digest[4-7]                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        MD5 Digest[8-11]                       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        MD5 Digest[12-15]                      |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

## TDDP Protocol Version
tddp_ver = "02"

## Packet Type
# 0x01	SET_USR_CFG - set configuration information
# 0x02	GET_SYS_INF - get configuration information
# 0x03	CMD_SPE_OPR - special configuration commands
# 0x04	HEART_BEAT -  the heartbeat package
tddp_type = "03"

## Code Request Type
# 0x01 TDDP_REQUEST
# 0x02 TDDP_REPLY
tddp_code = "01"

## Reply Info Status
# 0x00 REPLY_OK
# 0x02 ?
# 0x03 ?
# 0x09 REPLY_ERROR
# 0xFF ?
tddp_reply = "00"

## Packet Length (not including header)
# 4 bytes
tddp_length = "0000002A"

## Packet ID
# 2 bytes
# supposed to be incremented +1 for each packet
tddp_id = "0001"

# Subtype for CMD_SPE_OPR (Special Operations Command)
# Set to 0x00 for SET_USR_CFG and GET_SYS_INF
#
# Subtypes described in patent application, hex value unknown:
#  CMD_SYS_OPR     Router system operation, including: init, save, reboot, reset, clr dos
#  CMD_AUTO_TEST   MAC for writing operation, the user replies CMD_SYS_INIT broadcast packet
#  CMD_CONFIG_MAC  Factory settings MAC operations
#  CMD_CANCEL_TEST Cancel automatic test, stop receiving broadcast packets
#  CMD_GET_PROD_ID Get product ID
#  CMD_SYS_INIT    Initialize a router
#  CMD_CONFIG_PIN  Router PIN code
#
# Subtypes that seem to work for a HS-110 Smart Plug:
#  0x0A returns "ABCD0110"
#  0x12 returns the deviceID
#  0x14 returns the hwID
#  0x06 changes MAC
#  0x13 changes deviceID
#  0x15 changes deviceID
#
# Subtypes that seem to work for an Archer C9 Router:
#  0x0E returns physical status of WAN link:
#               wan_ph_link 1 0 = disconnected
#               wan_ph_link 1 1 = connected
#  0x0F returns logical status of WAN link: wan_logic_link 1 0
#  0x0A returns \x00\x09\x00\x01\x00\x00\x00\x00
#  0x15 returns \x01\x00\x00\x00\x00\x00\x00\x00
#  0x18 returns 1
tddp_subtype = cmd

# Reserved
tddp_reserved = "00"

# Digest 0-15 (32char/128bit/16byte)
# MD5 digest of entire packet
# Set to 0 initially for building the digest, then overwrite with result
tddp_digest = "%0.32X" % 00

# TDDP Data
# Always pad with 0x00 to a length divisible by 8
# We're not sending any data since we're only sending read commands
tddp_data = ""

# Recalculate length if sending data
tddp_length = len(tddp_data)/2
tddp_length = "%0.8X" % tddp_length

## Encrypt data with key
key = des(binascii.unhexlify(tddp_key), ECB)
data = key.encrypt(binascii.unhexlify(tddp_data))

## Assemble packet
tddp_packet = "".join([tddp_ver, tddp_type, tddp_code, tddp_reply, tddp_length, tddp_id, tddp_subtype, tddp_reserved, tddp_digest, data.encode('hex')])

# Calculate MD5
tddp_digest = hashlib.md5(binascii.unhexlify(tddp_packet)).hexdigest()
tddp_packet = tddp_packet[:24] + tddp_digest + tddp_packet[56:]

# Binding receive socket in advance in case reply comes fast.
sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_receive.bind(('', port_receive))

# Send a request
sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_send.sendto(binascii.unhexlify(tddp_packet), (ip, port_send))
if args.verbose:
	print "Raw Request:\t", tddp_packet
t = tddp_packet
print "Request Data:\tVersion", t[0:2], "Type", t[2:4], "Status", t[6:8], "Length", t[8:16], "ID", t[16:20], "Subtype", t[20:22]
sock_send.close()

# Receive the reply
response, addr = sock_receive.recvfrom(1024)
r = response.encode('hex')
if args.verbose:
	print "Raw Reply:\t", r
sock_receive.close()
print "Reply Data:\tVersion", r[0:2], "Type", r[2:4], "Status", r[6:8], "Length", r[8:16], "ID", r[16:20], "Subtype", r[20:22]

# Take payload and decrypt using key
recv_data = r[56:]
if recv_data:
	print "Decrypted:\t" + key.decrypt(binascii.unhexlify(recv_data))

