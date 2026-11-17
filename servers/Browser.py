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
from packets import SMBHeader, SMBNegoData, SMBSessionData, SMBTreeConnectData, RAPNetServerEnum3Data, SMBTransRAPData
import socketserver
from utils import *
import struct
import socket


def WorkstationFingerPrint(data):
	return {
		b"\x04\x00"    :"Windows 95",
		b"\x04\x10"    :"Windows 98",
		b"\x04\x90"    :"Windows ME",
		b"\x05\x00"    :"Windows 2000",
		b"\x05\x01"    :"Windows XP",
		b"\x05\x02"    :"Windows XP(64-Bit)/Windows 2003",
		b"\x06\x00"    :"Windows Vista/Server 2008",
		b"\x06\x01"    :"Windows 7/Server 2008R2",
		b"\x06\x02"    :"Windows 8/Server 2012",
		b"\x06\x03"    :"Windows 8.1/Server 2012R2",
		b"\x10\x00"    :"Windows 10/Server 2016",
	}.get(data, 'Unknown')


def RequestType(data):
	if isinstance(data, int):
		data = bytes([data])
	return {
		b"\x01": 'Host Announcement',
		b"\x02": 'Request Announcement',
		b"\x08": 'Browser Election',
		b"\x09": 'Get Backup List Request',
		b"\x0a": 'Get Backup List Response',
		b"\x0b": 'Become Backup Browser',
		b"\x0c": 'Domain/Workgroup Announcement',
		b"\x0d": 'Master Announcement',
		b"\x0e": 'Reset Browser State Announcement',
		b"\x0f": 'Local Master Announcement',
	}.get(data, 'Unknown')


def PrintServerName(data, entries):
	if entries <= 0:
		return None
	entrieslen = 26 * entries
	chunk_size = entrieslen // entries
	chunks = len(data[:entrieslen])
	ServerName = [data[i:i+chunk_size] for i in range(0, chunks, chunk_size)]

	l = []
	for x in ServerName:
		fingerprint = WorkstationFingerPrint(x[16:18])
		name = x[:16].replace(b'\x00', b'').decode('latin-1', errors='ignore')
		l.append('%s (%s)' % (name, fingerprint))
	return l


def ParsePacket(Payload):
	PayloadOffset = struct.unpack('<H', Payload[51:53])[0]
	StatusCode = Payload[PayloadOffset-4:PayloadOffset-2]

	if StatusCode == b"\x00\x00":
		EntriesNum = struct.unpack('<H', Payload[PayloadOffset:PayloadOffset+2])[0]
		return PrintServerName(Payload[PayloadOffset+4:], EntriesNum)
	return None


def RAPThisDomain(Client, Domain):        
	PDC = RapFinger(Client, Domain, b"\x00\x00\x00\x80")
	if PDC is not None:
		print(text("[LANMAN] Detected Domains: %s" % ', '.join(PDC)))
	
	SQL = RapFinger(Client, Domain, b"\x04\x00\x00\x00")
	if SQL is not None:
		print(text("[LANMAN] Detected SQL Servers on domain %s: %s" % (Domain, ', '.join(SQL))))

	WKST = RapFinger(Client, Domain, b"\xff\xff\xff\xff")
	if WKST is not None:
		print(text("[LANMAN] Detected Workstations/Servers on domain %s: %s" % (Domain, ', '.join(WKST))))


def RapFinger(Host, Domain, Type):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((Host, 445))
		s.settimeout(0.3)

		Header = SMBHeader(cmd=b"\x72", mid=b"\x01\x00")
		Body = SMBNegoData()
		Body.calculate()

		Packet = bytes(Header) + bytes(Body)
		Buffer = struct.pack(">i", len(Packet)) + Packet

		s.send(Buffer)
		data = s.recv(1024)

		# Session Setup AndX Request, Anonymous.
		if data[8:10] == b"\x72\x00":
			Header = SMBHeader(cmd=b"\x73", mid=b"\x02\x00")
			Body = SMBSessionData()
			Body.calculate()

			Packet = bytes(Header) + bytes(Body)
			Buffer = struct.pack(">i", len(Packet)) + Packet

			s.send(Buffer)
			data = s.recv(1024)

			# Tree Connect IPC$.
			if data[8:10] == b"\x73\x00":
				Header = SMBHeader(cmd=b"\x75", flag1=b"\x08", flag2=b"\x01\x00", uid=data[32:34], mid=b"\x03\x00")
				Body = SMBTreeConnectData(Path="\\\\" + Host + "\\IPC$")
				Body.calculate()

				Packet = bytes(Header) + bytes(Body)
				Buffer = struct.pack(">i", len(Packet)) + Packet

				s.send(Buffer)
				data = s.recv(1024)

				# Rap ServerEnum.
				if data[8:10] == b"\x75\x00":
					Header = SMBHeader(cmd=b"\x25", flag1=b"\x08", flag2=b"\x01\xc8", uid=data[32:34], tid=data[28:30], pid=data[30:32], mid=b"\x04\x00")
					Body = SMBTransRAPData(Data=RAPNetServerEnum3Data(ServerType=Type, DetailLevel=b"\x01\x00", TargetDomain=Domain))
					Body.calculate()

					Packet = bytes(Header) + bytes(Body)
					Buffer = struct.pack(">i", len(Packet)) + Packet

					s.send(Buffer)
					data = s.recv(64736)

					# Rap ServerEnum, Get answer and return what we're looking for.
					if data[8:10] == b"\x25\x00":
						s.close()
						return ParsePacket(data)
	except:
		pass

def BecomeBackup(data, Client):
	try:
		DataOffset    = struct.unpack('<H', data[139:141])[0]
		BrowserPacket = data[82+DataOffset:]
		ReqType       = RequestType(BrowserPacket[0:1])

		if ReqType == "Become Backup Browser":
			ServerName = BrowserPacket[1:]
			Domain     = Decode_Name(data[49:81])
			Name       = Decode_Name(data[15:47])
			Role       = NBT_NS_Role(data[45:48])

			if settings.Config.AnalyzeMode:
				print(text("[Analyze mode: Browser] Datagram Request from IP: %s hostname: %s via the: %s wants to become a Local Master Browser Backup on this domain: %s." % (Client, Name, Role, Domain)))
				RAPThisDomain(Client, Domain)

	except:
		pass

def ParseDatagramNBTNames(data, Client):
	try:
		Domain = Decode_Name(data[49:81])
		Name   = Decode_Name(data[15:47])
		Role1  = NBT_NS_Role(data[45:48])
		Role2  = NBT_NS_Role(data[79:82])

		if Role2 in ["Domain Controller", "Browser Election", "Local Master Browser"] and settings.Config.AnalyzeMode:
			print(text('[Analyze mode: Browser] Datagram Request from IP: %s hostname: %s via the: %s to: %s. Service: %s' % (Client, Name, Role1, Domain, Role2)))
			RAPThisDomain(Client, Domain)
	except:
		pass

class Browser(socketserver.BaseRequestHandler):

	def handle(self):
		try:
			request, socket_obj = self.request

			if settings.Config.AnalyzeMode:
				ParseDatagramNBTNames(request, self.client_address[0])
				BecomeBackup(request, self.client_address[0])
			BecomeBackup(request, self.client_address[0])

		except Exception:
			pass
