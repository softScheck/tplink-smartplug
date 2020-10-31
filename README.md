# TP-Link WiFi SmartPlug Client and Wireshark Dissector

For the full story, see [Reverse Engineering the TP-Link HS110](https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/)

## tplink_smartplug.py ##

A python client for the proprietary TP-Link Smart Home protocol to control TP-Link HS100 and HS110 WiFi Smart Plugs.
The SmartHome protocol runs on TCP port 9999 and uses a trivial XOR autokey encryption that provides no security. 

There is no authentication mechanism and commands are accepted independent of device state (configured/unconfigured).


Commands are formatted using JSON, for example:

  `{"system":{"get_sysinfo":null}}`

Instead of `null` we can also write `{}`. Commands can be nested, for example:

  `{"system":{"get_sysinfo":null},"time":{"get_time":null}}`

A full list of commands is provided in [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt).


#### Usage ####

   `./tplink_smartplug.py -t <ip> [-c <cmd> || -j <json>]`

Provide the target IP using `-t` and a command to send using either `-c` or `-j`. Commands for the `-c` flag:

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

When using commands from the `-c` list on power strips HS300 and HS303, you can use the `-o` flag to specify a specific outlet on the power strip using the child ID.
The child ID can be obtained by running the info command on the power strip at looking in the `"system"` > `"get_sysinfo"` > `"children"` sections.

More advanced commands such as creating or editing rules can be issued using the `-j` flag by providing the full JSON string for the command. Please consult [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt) for a comprehensive list of commands.

#### Modifying Commands for HS300 and HS303 for the `-j` flag ####

The same commands can be modified to control a single outlet by inserting `"context":{"child_ids":["CHILD_ID"]}, ` in front of `"system":`. If you dont specify a child outlet, the command will affect the entire power strip.

For instance:
`{"system":{"set_led_off":{"off":0}}}` Will turn all outlets off

`'{"context":{"child_ids":["8006...E101"]}, "system":{"set_led_off":{"off":0}}}'` Will turn just that one outlet on

You can specify multiple child outlet IDs by adding them to the `child_ids` array in your command.

Some commands are not outlet specific (ex. `info`) so the child ID(s) will be ignored by your power strip.


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
