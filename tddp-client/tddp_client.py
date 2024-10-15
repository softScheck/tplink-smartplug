#!/usr/bin/env python3

"""TP-Link Device Debug Protocol (TDDP) v2 Client.

Based on https://www.google.com/patents/CN102096654A?cl=en

HIGHLY EXPERIMENTAL and untested!
The protocol is available on all kinds of TP-Link devices such as routers,
cameras, smart plugs etc.

by Lubomir Stroetmann
Copyright 2016 softScheck GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import hashlib
import logging
import socket
import string
from binascii import hexlify, unhexlify

from pyDes import ECB, des

version = 0.4


def generate_tddp_key(username: str, password: str) -> str:
    """Generate TDDP DES Key."""
    return hashlib.md5(username.encode() + password.encode()).hexdigest()[:16]


def build_tddp_packet(cmd: str, tddp_key: str) -> str:
    """Build TDDP packet."""
    tddp_ver = "02"
    tddp_type = "03"
    tddp_code = "01"
    tddp_reply = "00"
    tddp_length = "0000002A"
    tddp_id = "0001"
    tddp_subtype = cmd
    tddp_reserved = "00"
    tddp_digest = f"{00:0032X}"
    tddp_data = ""

    tddp_length = len(tddp_data) // 2
    tddp_length = f"{tddp_length:008X}"

    key = des(unhexlify(tddp_key), ECB)
    data = key.encrypt(unhexlify(tddp_data))

    tddp_packet = "".join(
        [
            tddp_ver,
            tddp_type,
            tddp_code,
            tddp_reply,
            tddp_length,
            tddp_id,
            tddp_subtype,
            tddp_reserved,
            tddp_digest,
            hexlify(data.encode()).decode(),
        ]
    )

    tddp_digest = hashlib.md5(unhexlify(tddp_packet)).hexdigest()
    tddp_packet = tddp_packet[:24] + tddp_digest + tddp_packet[56:]

    logging.debug(f"Raw Request:\t{tddp_packet}")

    return tddp_packet


def send_request(ip: str, port_send: int, tddp_packet: str):
    """Send TDDP request."""
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_send.sendto(unhexlify(tddp_packet), (ip, port_send))
    logging.debug(
        f"Req Data:\tVersion {tddp_packet[0:2]} "
        f"Type {tddp_packet[2:4]} "
        f"Status {tddp_packet[6:8]} "
        f"Length {tddp_packet[8:16]} "
        f"ID {tddp_packet[16:20]} "
        f"Subtype {tddp_packet[20:22]}"
    )
    sock_send.close()


def receive_reply(port_receive: int) -> str:
    """Receive TDDP reply."""
    sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_receive.bind(("", port_receive))
    response, addr = sock_receive.recvfrom(1024)
    resp = hexlify(response).decode()
    logging.info(f"Raw Reply:\t{resp}")
    sock_receive.close()
    return resp


def decrypt_and_print_response(response: str, tddp_key: str):
    """Decrypt and print TDDP response."""
    key = des(unhexlify(tddp_key), ECB)
    recv_data = response[56:]
    if recv_data:
        logging.info(f"Decrypted:\t{key.decrypt(unhexlify(recv_data))}")


def parse_args():
    """Parse commandline arguments."""

    def valid_ip(ip: str) -> str:
        """Check if IP is valid."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except OSError:
            parser.error("Invalid IP Address.")
        return ip

    def valid_hex(cmd: str) -> str:
        """Check if command is two hex chars."""
        ishex = all(c in string.hexdigits for c in cmd)
        if not (len(cmd) == 2 and ishex):
            parser.error("Please issue a two-character hex command, e.g. 0A")
        return cmd

    parser = argparse.ArgumentParser(
        description=f"Experimental TP-Link TDDPv2 Client v.{version}"
    )
    parser.add_argument("-v", "--verbose", help="Verbose mode", action="store_true")
    parser.add_argument(
        "-t",
        "--target",
        metavar="<ip>",
        required=True,
        help="Target IP Address",
        type=valid_ip,
    )
    parser.add_argument(
        "-u",
        "--username",
        metavar="<username>",
        help="Username (default: admin)",
        default="admin",
    )
    parser.add_argument(
        "-p",
        "--password",
        metavar="<password>",
        help="Password (default: admin)",
        default="admin",
    )
    parser.add_argument(
        "-c",
        "--command",
        metavar="<hex>",
        required=True,
        help="Command value to send as hex (e.g. 0A)",
        type=valid_hex,
    )
    return parser.parse_args()


def main():
    """Parse arguments, generate key, build and send tddp packet,
    decrypt and print response.
    """
    args = parse_args()
    ip = args.target
    cmd = args.command
    username = args.username
    password = args.password
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    port_send = 1040
    port_receive = 61000

    tddp_key = generate_tddp_key(username, password)
    logging.info(f"TDDP Key:\t{tddp_key} ({username}:{password})")
    tddp_packet = build_tddp_packet(cmd, tddp_key)
    send_request(ip, port_send, tddp_packet)
    response = receive_reply(port_receive)
    decrypt_and_print_response(response, tddp_key)


if __name__ == "__main__":
    main()
