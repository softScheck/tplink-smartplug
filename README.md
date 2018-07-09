# TP-Link WiFi SmartPlug Client and Wireshark Dissector

For the full story, see [Reverse Engineering the TP-Link HS110](https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/)

## tplink_smartplug.py ##

A python client for the proprietary TP-Link Smart Home protocol to control TP-Link HS100 and HS110 WiFi Smart Plugs.
The SmartHome protocol runs on TCP/UDP port 9999 and uses a trivial XOR autokey encryption that provides no security. 
Other TP-Link products use the same protocol (such as LB-XXX lightbulbs), but may not be compatible with command templates like `on` or `off`.

There is no authentication mechanism and commands are accepted independent of device state (configured/unconfigured).


Commands are formatted using JSON, for example:

  `{"system":{"get_sysinfo":null}}`

Instead of `null` we can also write `{}`. Commands can be nested, for example:

  `{"system":{"get_sysinfo":null},"time":{"get_time":null}}`

A full list of commands is provided in [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt).


#### Usage ####

   `./tplink_smartplug.py [-h] (-t <hostname> | -b)
                           [-c <command> | -j <JSON string>] [-u]
                           [-s <address>] [-T <seconds>]`


Provide the target IP using `-t` and a command to send using either `-c` or `-j`. Use `-u` to use UDP instead of TCP, and use `-b` to send to the 255.255.255.255 broadcast address (also UDP). To send from a specific source address, specify the address with `-s`. To specify a timeout to wait for all devices to reply to a broadcast, use `-T` (also applies to UDP, default 0.5 seconds). When sending a broadcast, the script will dump all responses received and wait until timeout.

Predefined commands for the `-c` flag:

| Command   | Description                          |
|-----------|--------------------------------------|
| on        | Turns on the plug                    |
| off       | Turns off the plug                   |
| info      | Returns device info                  |
| cloudinfo | Returns cloud connectivity info      |
| wlanscan  | Scan for nearby access points        |
| time      | Returns the system time              |
| schedule  | Lists configured schedule rules      |
| countdown | Lists configured countdown rules     |
| antitheft | Lists configured antitheft rules     |
| reboot    | Reboot the device                    |
| reset     | Reset the device to factory settings |
| energy    | Return realtime voltage/current/power|

(when no command and no JSON string specified, `info` is used by default)


More advanced commands such as creating or editing rules can be issued using the `-j` flag by providing the full JSON string for the command. Please consult [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt) for a comprehensive list of commands.

## Wireshark Dissector ##

Wireshark dissector to decrypt TP-Link Smart Home Protocol packets (TCP port 9999).

![ScreenShot](wireshark-dissector.png)

#### Installation ####

Copy [tplink-smarthome.lua](tplink-smarthome.lua) into:

| OS          | Installation Path            |
|-------------|------------------------------|
| Windows     | %APPDATA%\Wireshark\plugins\ |
| Linux/MacOS | $HOME/.wireshark/plugins     |

## tddp-client.py ##

A proof-of-concept python client to talk to a TP-Link device using the **TP-Link Device Debug Protocol (TDDP)**.

TDDP is implemented across a whole range of TP-Link devices including routers, access points, cameras and smartplugs.
TDDP can read and write a device's configuration and issue special commands. UDP port 1040 is used to send commands, replies come back on UDP port 61000. This client has been tested with a TP-Link Archer C9 Wireless Router and a TP-Link HS-110 WiFi Smart Plug.

TDDP is a binary protocol documented in patent [CN102096654A](https://www.google.com/patents/CN102096654A?cl=en).

Commands are issued by setting the appropriate values in the Type and SubType header fields.
Data is returned DES-encrypted and requires the username and password of the device to decrypt. Likewise, configuration data to be written to the device needs to be sent encrypted. The DES key is constructed by taking the MD5 hash of username and password concatenated together, and then taking the first 8 bytes of the MD5 hash.

#### Usage ####

   `./tddp-client.py -t <ip> -u username -p password -c 0A`

Provide the target IP using -t. You can provide a username and password, otherwise admin/admin is used as a default. They are necessary to decrypt the data that is returned.

Provide the command as a two-character hex string, e.g. -c 0A. What type of data a command might read out will be different for various TP-Link devices.

#### Example ####
Reading out the WAN link status on an Archer C9 in default configuration shows the link is down (0):
   ```
   ./tddp-client.py -t 192.168.0.1 -c 0E
   Request Data: Version 02 Type 03 Status 00 Length 00000000 ID 0001 Subtype 0e
   Reply Data:   Version 02 Type 03 Status 00 Length 00000018 ID 0001 Subtype 0e
   Decrypted:    wan_ph_link 1 0
   ```
