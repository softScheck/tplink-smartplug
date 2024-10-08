#!/usr/bin/env python3
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

import argparse
import socket
from struct import pack

import binascii
import socket
import requests

# pycryptodome
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter, Padding

import logging
import hashlib
import time
import json

import http.client as http_client

version = 0.4

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

    if ((port <= 1024) or (port > 65535)):
        parser.error("Invalid port number.")

    return port


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
            'on'       : '{"system":{"set_relay_state":{"state":1}}}',
            'off'      : '{"system":{"set_relay_state":{"state":0}}}',
            'ledoff'   : '{"system":{"set_led_off":{"off":1}}}',
            'ledon'    : '{"system":{"set_led_off":{"off":0}}}',
            'cloudinfo': '{"cnCloud":{"get_info":{}}}',
            'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
            'time'     : '{"time":{"get_time":{}}}',
            'schedule' : '{"schedule":{"get_rules":{}}}',
            'countdown': '{"count_down":{"get_rules":{}}}',
            'antitheft': '{"anti_theft":{"get_rules":{}}}',
            'reboot'   : '{"system":{"reboot":{"delay":1}}}',
            'reset'    : '{"system":{"reset":{"delay":1}}}',
            'energy'   : '{"emeter":{"get_realtime":{}}}',
            'energy_reset'   : '{"emeter":{"erase_emeter_stat":{}}}',
            'runtime_reset'   : '{"schedule":{"erase_runtime_stat":{}}}'
}

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171

def encrypt(string):
    key = 171
    result = pack(">I", len(string))
    for i in string:
        a = key ^ ord(i)
        key = a
        result += bytes([a])
    return result

def decrypt(string):
    key = 171
    result = []
    for i in string:
        a = key ^ i
        key = i
        result.append(a)
    return bytearray(result).decode('utf-8')

# New TP-Link HS110 handshake protocol
# Classes EncryptionSession and Handshake, and function encrypt2 based on:
#  https://gist.github.com/chriswheeldon/3b17d974db3817613c69191c0480fe55

class EncryptionSession:
    def __init__(self, local_seed, remote_seed, user_hash):
        self._key = self._key_derive(local_seed, remote_seed, user_hash)
        (self._iv, self._seq) = self._iv_derive(local_seed, remote_seed, user_hash)
        self._sig = self._sig_derive(local_seed, remote_seed, user_hash)

    def _key_derive(self, local_seed, remote_seed, user_hash):
        payload = 'lsk'.encode('utf-8') + local_seed + remote_seed + user_hash
        return hashlib.sha256(payload).digest()[:16]

    def _iv_derive(self, local_seed, remote_seed, user_hash):
        # iv is first 16 bytes of sha256, where the last 4 bytes forms the
        # sequence number used in requests and is incremented on each request
        payload = 'iv'.encode('utf-8') + local_seed + remote_seed + user_hash
        iv = hashlib.sha256(payload).digest()[:16]
        return (iv[:12], (int.from_bytes(iv[12:16], 'big') & 0x7fffffff))

    def _sig_derive(self, local_seed, remote_seed, user_hash):
        # used to create a hash with which to prefix each request
        payload = 'ldk'.encode('utf-8') + local_seed + remote_seed + user_hash
        return hashlib.sha256(payload).digest()[:28]

    def iv(self):
        seq = self._seq.to_bytes(4, 'big')
        iv = self._iv + seq
        assert(len(iv) == 16)
        return iv

    def encrypt(self, msg):
        self._seq = self._seq + 1
        if (type(msg) == str):
            msg = msg.encode('utf-8')
        assert(type(msg) == bytes)
        cipher = AES.new(self._key, AES.MODE_CBC, self.iv())
        ciphertext = cipher.encrypt(Padding.pad(msg, AES.block_size))
        signature = hashlib.sha256(self._sig + self._seq.to_bytes(4, 'big') + ciphertext).digest()
        return (signature + ciphertext, self._seq)

    def decrypt(self, msg):
        assert(type(msg) == bytes)
        cipher = AES.new(self._key, AES.MODE_CBC, self.iv())
        plaintext = Padding.unpad(cipher.decrypt(msg[32:]), AES.block_size)
        return plaintext

class Handshake:
    def __init__(self, ip):
        self.ip = ip
        self.local_seed = Random.get_random_bytes(16)

    def user_hash(self):
        # md5(md5(email) + md5(pass))
        # device is not connected to tplink cloud i.e. email and pass are empty
        # may need to include your email and password below if app/plug are associated with a tplink account?
        # i.e. user_hash = hashlib.md5(b'<email>').digest() + hashlib.md5(b'<pass>').digest()
        user_hash = hashlib.md5(b'').digest() + hashlib.md5(b'').digest()
        return hashlib.md5(user_hash).digest()

    def perform(self, http_session):
        # step 1 - send our seed
        result = http_session.post('http://{}:80/app/handshake1'.format(self.ip), data=self.local_seed)
        assert(result.status_code == 200)
        body = result.content
        self.remote_seed = body[:16]
        assert(hashlib.sha256(self.local_seed + self.user_hash()).digest() == body[16:]) # device responds with hash of seed + user hash

        # step 2 - send hash of remote seed + user hash
        payload = hashlib.sha256(self.remote_seed + self.user_hash()).digest()
        result = http_session.post('http://{}:80/app/handshake2'.format(self.ip), data=payload)
        assert(result.status_code == 200)

        return EncryptionSession(self.local_seed, self.remote_seed, self.user_hash())

def encrypt2(session, ip, string):
    handshake = Handshake(ip)
    retry = 0

    while retry < 9:
        encryption = handshake.perform(session)
        (msg, seq) = encryption.encrypt(string)
        res = session.post('http://{}:80/app/request'.format(ip), params={'seq': seq}, data=msg)
        if res.status_code == 200:
            break
        retry += 1
        time.sleep(0.25)
    assert(res.status_code == 200)
    return(encryption.decrypt(res.content).decode("utf-8"))


# Parse commandline arguments
parser = argparse.ArgumentParser(description=f"TP-Link Wi-Fi Smart Plug Client v{version}")
parser.add_argument("-t", "--target", metavar="<hostname>", required=True,
                    help="Target hostname or IP address", type=validHostname)
parser.add_argument("-p", "--port", metavar="<port>", default=9999,
                    required=False, help="Target port", type=validPort)
parser.add_argument("-q", "--quiet", dest="quiet", action="store_true",
                    help="Only show result")
parser.add_argument("--timeout", default=10, required=False,
                    help="Timeout to establish connection")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>",
                   help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
group.add_argument("-j", "--json", metavar="<JSON string>",
                   help="Full JSON string of command to send")
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
    sock_tcp.settimeout(int(args.timeout))
    sock_tcp.connect((ip, port))
    sock_tcp.settimeout(None)
    sock_tcp.send(encrypt(cmd))
    data = sock_tcp.recv(2048)
    sock_tcp.close()

    decrypted = decrypt(data[4:])

    if args.quiet:
        print(decrypted)
    else:
        print("Sent:     ", cmd)
        print("Received: ", decrypted)

except socket.error:
    try:
        session = requests.Session()
        port = 80
        response = encrypt2(session, ip, cmd)
        if args.quiet:
            print(response)
        else:
            print("Sent:     ", cmd)
            print("Received: ", response)
    except socket.error:
        quit(f"Could not connect to host {ip}:{port}")
