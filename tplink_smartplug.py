#!/usr/bin/env python3

"""TP-Link Wi-Fi Smart Plug Protocol client (TP-Link HS-100, HS-110, ...).

Orignal author: Lubomir Stroetmann
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
import socket
from struct import pack

version = 0.4


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink-smarthome-commands.txt
commands = {
    "antitheft": '{"anti_theft":{"get_rules":{}}}',
    "cloudinfo": '{"cnCloud":{"get_info":{}}}',
    "countdown": '{"count_down":{"get_rules":{}}}',
    "energy_reset": '{"emeter":{"erase_emeter_stat":{}}}',
    "energy": '{"emeter":{"get_realtime":{}}}',
    "info": '{"system":{"get_sysinfo":{}}}',
    "ledoff": '{"system":{"set_led_off":{"off":1}}}',
    "ledon": '{"system":{"set_led_off":{"off":0}}}',
    "off": '{"system":{"set_relay_state":{"state":0}}}',
    "on": '{"system":{"set_relay_state":{"state":1}}}',
    "reboot": '{"system":{"reboot":{"delay":1}}}',
    "reset": '{"system":{"reset":{"delay":1}}}',
    "runtime_reset": '{"schedule":{"erase_runtime_stat":{}}}',
    "schedule": '{"schedule":{"get_rules":{}}}',
    "time": '{"time":{"get_time":{}}}',
    "wlanscan": '{"netif":{"get_scaninfo":{"refresh":0}}}',
}


def encrypt(string: str) -> bytes:
    """Encryption of TP-Link Smart Home Protocol.
    XOR Autokey Cipher with starting key = 171.
    """
    key = 171
    result = pack(">I", len(string))
    for i in string:
        a = key ^ ord(i)
        key = a
        result += bytes([a])
    return result


def decrypt(ciphertext: bytes) -> bytearray:
    """Decryption of TP-Link Smart Home Protocol.
    XOR Autokey Cipher with starting key = 171.
    """
    key = 171
    result = []
    for i in ciphertext:
        a = key ^ i
        key = i
        result.append(a)
    return bytearray(result).decode()


def parse_args():
    """Parse commandline arguments."""

    def valid_hostname(hostname: str) -> str:
        """Check if hostname is valid."""
        try:
            socket.gethostbyname(hostname)
        except OSError:
            parser.error("Invalid hostname.")
        return hostname

    def valid_port(port: str) -> int:
        """Check if port is valid."""
        print(type(port))
        try:
            port = int(port)
        except ValueError:
            parser.error("Invalid port number.")

        if (port <= 1024) or (port > 65535):
            parser.error("Invalid port number.")

        return port

    parser = argparse.ArgumentParser(
        description=f"TP-Link Wi-Fi Smart Plug Client v{version}"
    )
    parser.add_argument(
        "-t",
        "--target",
        metavar="<hostname>",
        required=True,
        help="Target hostname or IP address",
        type=valid_hostname,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<port>",
        default=9999,
        required=False,
        help="Target port",
        type=valid_port,
    )
    parser.add_argument(
        "-q", "--quiet", dest="quiet", action="store_true", help="Only show result"
    )
    parser.add_argument(
        "--timeout", default=10, required=False, help="Timeout to establish connection"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--command",
        metavar="<command>",
        help="Preset command to send. Choices are: " + ", ".join(commands),
        choices=commands,
    )
    group.add_argument(
        "-j",
        "--json",
        metavar="<JSON string>",
        help="Full JSON string of command to send",
    )
    return parser.parse_args()


def main():
    """Read argument, send encrypted commands, output decrypted answer."""
    args = parse_args()
    # Set target IP, port and command to send
    ip = args.target
    port = args.port
    cmd = args.json if args.command is None else commands[args.command]

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

    except OSError:
        print(f"Could not connect to host {ip}:{port}")


if __name__ == "__main__":
    main()
