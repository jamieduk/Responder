#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket
import struct

from utils import color
from packets import SMBHeader, SMBNego, SMBNegoFingerData, SMBSessionFingerData

def OsNameClientVersion(data):
	try:
		length = struct.unpack('<H', data[43:45])[0]
		sub_data = data[47+length:]
		parts = [e.replace(b'\x00', b'').decode('latin-1') for e in sub_data.split(b'\x00\x00\x00')[:2]]
		return parts[0], parts[1]
	except:
		return "Could not fingerprint Os version.", "Could not fingerprint LanManager Client version"

def RunSmbFinger(host):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(host)
		s.settimeout(0.7)

		h = SMBHeader(cmd=b"\x72", flag1=b"\x18", flag2=b"\x53\xc8")
		n = SMBNego(data=SMBNegoFingerData())
		n.calculate()
		
		Packet = bytes(h) + bytes(n)
		Buffer = struct.pack(">i", len(Packet)) + Packet
		s.send(Buffer)
		data = s.recv(2048)
		
		if data[8:10] == b"\x72\x00":
			Header = SMBHeader(cmd=b"\x73", flag1=b"\x18", flag2=b"\x17\xc8", uid=b"\x00\x00")
			Body = SMBSessionFingerData()
			Body.calculate()

			Packet = bytes(Header) + bytes(Body)
			Buffer = struct.pack(">i", len(Packet)) + Packet  

			s.send(Buffer) 
			data = s.recv(2048)

		if data[8:10] == b"\x73\x16":
			return OsNameClientVersion(data)
	except:
		print(color("[!] ", 1, 1) + " Fingerprint failed")
		return None
