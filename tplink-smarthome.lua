-- TP-Link Smart Home Protocol (Port 9999) Wireshark Dissector
-- For decrypting local network traffic between TP-Link 
-- Smart Home Devices and the Kasa Smart Home App
--
-- Install under:
-- (Windows)      %APPDATA%\Wireshark\plugins\
-- (Linux, Mac)   $HOME/.wireshark/plugins
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
p_tplink = Proto ("TPLink-SmartHome","TP-Link Smart Home Protocol")

-- Dissector function
function p_tplink.dissector (buf, pkt, root)
  -- Validate packet length
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_tplink.name
 
  -- Decode data
        local ascii = ""
		local hex = ""
		
		-- Skip first 4 bytes (header)
        start = 4
        endPosition = buf:len() - 1
		
		-- Decryption key is -85 (256-85=171)
		local key = 171

		-- Decrypt Autokey XOR
		-- Save results as ascii and hex
        for index = start, endPosition do
          local c = buf(index,1):uint()
		  -- XOR first byte with key
		  d = bit32.bxor(c,key)
		  -- Use byte as next key
		  key = c
		 
		  hex = hex .. string.format("%x", d)
          -- Convert to printable characters
          if d >= 0x20 and d <= 0x7E then
            ascii = ascii .. string.format("%c", d)
          else
            -- Use dot for non-printable bytes
            ascii = ascii .. "."
          end
        end

  
  -- Create subtree
  subtree = root:add(p_tplink, buf(0))
  
  -- Add data to subtree
  subtree:add(ascii)
  -- Description of payload
  subtree:append_text(" (decrypted)")
  
  -- Call JSON Dissector with decrypted data
  local b = ByteArray.new(hex)
  local tvb = ByteArray.tvb(b, "JSON TVB")
  Dissector.get("json"):call(tvb, pkt, root)
 
end
 
-- Initialization routine
function p_tplink.init()
end
 
-- Register a chained dissector for port 9999
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(9999)
tcp_dissector_table:add(9999, p_tplink)