# TP-Link WiFi SmartPlug Client and Wireshark Dissector

## tplink-smartplug.py ##

A python client for the proprietary TP-Link Smart Home protocol to control TP-Link HS100 and HS110 WiFi Smart Plugs.
The SmartHome protocol runs on UDP port 9999 and uses a trivial XOR autokey encryption that provides no security. 

There is no authentication mechanism and commands are accepted independent of device state (configured/unconfigured).


Commands are formatted using JSON, for example:

  `{"system":{"get_sysinfo":null}}`

Instead of `null` we can also write `{}`. Commands can be nested, for example:

  `{"system":{"get_sysinfo":null},"time":{"get_time":null}}`

A full list of commands is provided in [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt).


#### Usage ####

   `./tplink-smarthome.py -t <ip> [-c <cmd> || -j <json>]`

Provide the target IP using `-t` and a command to send using either `-c` or `-j`. Commands for the `-c` flag:

| Command   | Description                          |
|-----------|--------------------------------------|
| on        | Turns on the plug                    |
| off       | Turns off the plug                   |
| system    | Returns device info                  |
| cloudinfo | Returns cloud connectivity info      |
| wlanscan  | Scan for nearby access points        |
| time      | Returns the system time              |
| schedule  | Lists configured schedule rules      |
| countdown | Lists configured countdown rules]    |
| antitheft | Lists configured antitheft rules     |
| reboot    | Reboot the device                    |
| reset     | Reset the device to factory settings |

More advanced commands such as creating or editing rules can be issued using the `-j` flag by providing the full JSON string for the command. Please consult [tplink-smarthome-commands.txt](tplink-smarthome-commands.txt) for a comprehensive list of commands.

## Wireshark Dissector ##

Wireshark dissector to decrypt TP-Link Smart Home Protocol packets (UDP port 9999).

![ScreenShot](wireshark-dissector.PNG)

#### Installation ####

Copy [tplink-smarthome.lua](tplink-smarthome.lua) into:

| OS          | Installation Path            |
|-------------|------------------------------|
| Windows     | %APPDATA%\Wireshark\plugins\ |
| Linux/MacOS | $HOME/.wireshark/plugins     |

## tddp-client.py ##

A proof-of-concept python client to talk to a TP-Link device using the **TP-Link Device Debug Protocol (TDDP)**.

TDDP is implemented across a whole range of TP-Link devices including routers, access points, cameras and smartplugs.
TDDP can read and write a device's configuration and issue special commands. On the HS110 SmartPlug it uses UDP port 1040, but might use different ports on other devices.

TDDP is a binary protocol documented in patent [CN102096654A](https://www.google.com/patents/CN102096654A?cl=en).

Commands are issued by setting the appropriate values in the Type and SubType header fields.
Data is returned DES-encrypted and requires the username and password of the device to decrypt. Likewise, configuration data to be written to the device needs to be sent encrypted. The DES key is constructed by taking the MD5 hash of username and password concatenated together, and then taking the first 8 bytes of the MD5 hash.

#### Usage ####

   `./tddp-client.py -t <ip> -u username -p password -c [test1|test2|test3]`

Provide the target IP using -t. You can provide a username and password, otherwise admin/admin is used as a default. They are necessary to decrypt the data that is returned.

Only three basic data readout commands (`test1, test2, test3`) are implemented. They are named test since it is unclear what type of data they might read out on different type of devices.
