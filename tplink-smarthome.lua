-- TP-Link Smart Home Protocol (Port 9999) Wireshark Dissector
-- For decrypting local network traffic between TP-Link 
-- Smart Home Devices and the Kasa Smart Home App
--
-- Install in the location listed in About Wireshark/Folders/Personal Plugins
--
-- by Lubomir Stroetmann
-- Copyright 2016 softScheck GmbH 
-- 
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--

-- Create TP-Link Smart Home protocol and its fields
hs1x0_proto_TCP = Proto ("TPLink-SmartHome-TCP", "TP-Link Smart Home Protocol (TCP")
hs1x0_proto_UDP = Proto ("TPLink-SmartHome-UDP", "TP-Link Smart Home Protocol (UDP)")

-- Decrypt string Autokey XOR to ByteArray
function tpdecode(buf, start)
  local key = 171
  local size = buf:len()-1
  local decoded = ""
  for i=start,size do
    local c = buf(i,1):uint()
    decoded = decoded .. string.format("%x", bit.bxor(c,key))
    key = c
  end
  return ByteArray.new(decoded)
end

function hs1x0_proto_TCP.dissector (buf, pkt, root)
  pkt.cols.protocol = "TPLink-SmartHome (TCP)"
  local subtree = root:add(hs1x0_proto_TCP, buf() ,"TPLink-SmartHome")
  local decoded = tpdecode(buf, 4)
  subtree:add(decoded:raw())
  subtree:append_text(" (decrypted)")
  local tvb = ByteArray.tvb(decoded, "JSON TVB")
  Dissector.get("json"):call(tvb, pkt, root)
end

function hs1x0_proto_UDP.dissector (buf, pkt, root)
  pkt.cols.protocol = "TPLink-SmartHome (UDP)"
  local subtree = root:add(hs1x0_proto_UDP, buf() ,"TPLink-SmartHome")
  local decoded = tpdecode(buf, 0)
  subtree:add(decoded:raw())
  subtree:append_text(" (decrypted)")
  local tvb = ByteArray.tvb(decoded, "JSON TVB")
  Dissector.get("json"):call(tvb, pkt, root)
end

tcp_table = DissectorTable.get ("tcp.port")
udp_table = DissectorTable.get ("udp.port")

-- register the protocol to port 9999
tcp_table:add (9999, hs1x0_proto_TCP)
udp_table:add (9999, hs1x0_proto_UDP)
