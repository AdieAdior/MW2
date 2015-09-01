# -*- coding: utf-8 -*-


from urllib import request
import json
import re
import struct
import codecs
from tabulate import tabulate
import ipaddress
import binascii
import geoip2.database
import time
import inspect
import platform
import gc
import sys
import string


reader = geoip2.database.Reader("GeoLite2-City.mmdb")

class userLookup:
	city = country = region = location = ""
	def __init__(self, ip):
		try:
			self.ip = reader.city(ip)
			self.city = self.ip.city.name
			self.country = self.ip.country.name
			self.region = self.ip.subdivisions.most_specific.name
			self.location = "%s, %s, %s" % (self.country, self.region, self.city)
		except:
			self.city = self.country = self.region = "?"

clear = "\n" * 100

def lineno():
		"""Returns the current line number in our program."""
		return inspect.currentframe().f_back.f_lineno

data1 = b'000eb629dda50024386330410800452803ad0d8200007611a40f188ca42da78e2b3f712071200399489bffffffff30706172747973746174650067a12a00040900000000000000002e000000a0b52d0000000000000c000444da4dddaec6dd4ddac0a80111188ca42d2071207100000000000000000000000000000000000000000000000000000000000000000000000000000000bedc085300008601080b080209040d0500070f02000000003f038046627c7c476c656e6e3231350000000000b8626a0b010010010a00000a49bdb76720712071000000000000000000000000000000000000000000000000c8e128859f28e1c800000145021a0000002478020001b1cf8072696c6579636872697300000000003f2aa10b01001001c0a802108e4451ef20712071000000000000000000000000000000000000000000000000cb003bc50d4100cb102602060e01600000000b00004002dc3340426c61636b73686565702c2057622e0000000000609fd30001001001c0a80154326ea4b320712071000000000000000000000000000000000000000000000000e07ee68f95e67ee024000000450a83000000088a001003ef0c185e3941706f6c6c6f2773205e31353063616c0000000000761ed10d01001001c0a8019c47c72b15207120710000000000000000000000000000000000000000000000008805f4fb2ef405889d960003450102000000a40900e4043f03885be299a3444953e299a35d4c41205375726665720000000000fc323b0601001001c0a80111188ca42d2071207100000000000000000000000000000000000000000000000014af948ea694af14d60105450058000000850c030005d1cb80436f6d726164654563686f0000000000cefe8d0401001001c0a80164a78e2b3f207120710000000000000000000000000000000000000000000000009d761e3cb91f769d628a02034509b900000041fe004006fc11404d7973744f66446561746800000000002a52520101001001c0a8017562f9268720712071000000000000000000000000000000000000000000000000e07ee68f95e67ee0540000004501fdffffff0656001009ff0030746f6861313937380000000000c89c350401001001c0a801665bc7230120712071000000000000000000000000000000000000000000000000585e613b3d615e5802aa00063907bdffffff000000cc0a1f004e5e314b616e6500000000000d77b90b010010010a46f0218189a5fb20719e7400000000000000000000000000000000000000000000000009f087e11d87f009c80003450a3f000000bd780800'







data1 = data1.replace(b" ", b"")

def sanityCheck(packet):
	if packet[10] >= 0:#points
		if packet[11] >= 0:#deaths
			if 0 <= packet[12] <= 69:#rank
				if packet[10] % 10 is 0:#rank
					if 0 <= packet[13] <= 11:#presteige
						if packet[0] in range(0x00, 0x0f):
							return True

	return False

def dec2ip(ip):
	ip2 = struct.pack("<L", ip)
	return str(ipaddress.ip_address(ip2))

vac = {}
def vacCheck(steamID, ip):
	if vac.get(steamID) is None:
		vac[steamID] = {"data":"", "time":0}
	if vac.get(steamID).get("time") < time.time() - 3600:
		steamKey = open('steamAPI.txt').read()
		url = "http://api.steampowered.com/ISteamUser/GetPlayerBans/v1/?key=%s&steamids=%s"%(steamKey, steamID)
		req = request.urlopen(url)
		encoding = req.headers.get_content_charset()
		obj = json.loads(req.read().decode(encoding))
		if obj["players"][0]["VACBanned"] is False:
			vac[steamID]["data"] = "False"
			vac[steamID]["time"] = time.time()
			return "False"
		else:
			vac[steamID]["data"] = "%d VAC ban(s) %d days ago"%(obj["players"][0]["NumberOfVACBans"],obj["players"][0]["DaysSinceLastBan"])
			vac[steamID]["time"] = time.time()
			if "Windows" not in platform.platform():
				subprocess.check_output(["easyrule block WAN %s"%ip], shell=True)
				subprocess.check_output(["pfctl -k %s"%ip], shell=True)
				subprocess.check_output(["pfctl -k 0.0.0.0/0 -k %s"%ip], shell=True)
			print("\033[1;31m%s BANNED - VAC\033[1;m"%ip)
			return "%d VAC ban(s) %d days ago"%(obj["players"][0]["NumberOfVACBans"],obj["players"][0]["DaysSinceLastBan"])
	else:
		return vac.get(steamID).get("data")

hours = {}

def gameCheck(steamID):
	if hours.get(steamID) is None:
		hours[steamID] = {"data":"", "time":0}
	if hours.get(steamID).get("time") < time.time() - 3600:
		steamKey = open('steamAPI.txt').read()
		url = "http://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/?key=%s&steamid=%s&format=json"%(steamKey, steamID)
		req = request.urlopen(url)
		encoding = req.headers.get_content_charset()
		obj = json.loads(req.read().decode(encoding))
		if obj.get("response") is not None:
			if obj["response"].get("games") is not None:
				for each in obj["response"]["games"]:
					if each["appid"] == 10190:
						hours[steamID]["data"] = int(each.get("playtime_forever")/60)
						hours[steamID]["time"] = time.time()
						return int(each.get("playtime_forever")/60)
				return "N/A"
			else:
				return "private"
		else:
			return "private"
	else:
		return hours.get(steamID).get("data")

def removecolour(value):
	if "Windows" in platform.platform():
		value = value.replace("^1", "")
		value = value.replace("^2", "")
		value = value.replace("^3", "")
		value = value.replace("^4", "")
		value = value.replace("^5", "")
		value = value.replace("^6", "")
		value = value.replace("^7", "")
		value = value.replace("^8", "")
		value = value.replace("^9", "")
		value = value.replace("^0", "")
		return ''.join(filter(lambda x:x in string.printable, value))
	else:
		newstring = value.replace("^1",    "\x1b[1;31m")#red
		newstring = newstring.replace("^2", "\x1b[1;32m")#green
		newstring = newstring.replace("^3", "\x1b[1;33m")#yellow
		newstring = newstring.replace("^4", "\x1b[1;34m")#blue
		newstring = newstring.replace("^5", "\x1b[1;36m")#cyan
		newstring = newstring.replace("^6", "\x1b[1;35m")#pink
		newstring = newstring.replace("^7", "\x1b[1;37m")#white
		newstring = newstring.replace("^8", "\x1b[1;m")#black
		newstring = newstring.replace("^9", "\x1b[1;30m")#grey
		newstring = newstring.replace("^0", "\x1b[1;m")#black
		if value != newstring:
			return newstring + "\x1b[1;m"
		else:
			return ''.join(filter(lambda x:x in string.printable, value))
f = open('bytes.log', 'w')
f.write("")
f.close()

global packetID
packetID = 0

def buff(data):
	global packetID
	copydata = data
	if 1 == 1:
		table = [["ID", "Name", "External IP", "Internal IP", "Steam ID", "Hours", "Location"]]
		if "Windows" in platform.platform():
			data = codecs.decode(data, "hex")
		else:
			data = bytes(data)
		data = data[42:]
		offset = 130
		if re.search(b"0partystate", data) is not None:
			# print(lineno())
			while offset  < len(data):
				# print(lineno())
				result = re.search(b'.+?\x00{24}.{21}',data[offset:] , re.DOTALL)
				if result is not None:
					a = result.group()
					nameLength = len(a) - 74
					unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIhbbbq'%nameLength, a)
					if sanityCheck(unpackedPacket):
						user = userLookup(str(dec2ip(unpackedPacket[5])))
						table.append([
									  unpackedPacket[0],
									  removecolour(unpackedPacket[2].decode("ascii", "ignore")),
									  dec2ip(unpackedPacket[5]),
									  dec2ip(unpackedPacket[4]),
									  unpackedPacket[3],
									  # unpackedPacket[10],
									  # unpackedPacket[11],
									  # unpackedPacket[12]+1,
									  # unpackedPacket[13],
									  vacCheck(unpackedPacket[3],
									  dec2ip(unpackedPacket[5])),
									  gameCheck(unpackedPacket[3]),
									  "%s, %s, %s" % (user.country, user.region, user.city)])
						offset = offset + len(a)
					else: 
						result = re.search(b'.+?\x00{24}.{22}', data[offset:], re.DOTALL)
						if result is not None:
							a = result.group()
							nameLength = len(a) - 75
							unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIxhbbbq'%nameLength, a)
							if sanityCheck(unpackedPacket):
								user = userLookup(str(dec2ip(unpackedPacket[5])))
								table.append([
											  unpackedPacket[0],
											  removecolour(unpackedPacket[2].decode("ascii", "ignore")),
											  dec2ip(unpackedPacket[5]),
											  dec2ip(unpackedPacket[4]),
											  unpackedPacket[3],
											  # unpackedPacket[10],
											  # unpackedPacket[11],
											  # unpackedPacket[12]+1,
											  # unpackedPacket[13],
											  vacCheck(unpackedPacket[3],
											  dec2ip(unpackedPacket[5])),
											  gameCheck(unpackedPacket[3]),
											  "%s, %s, %s" % (user.country, user.region, user.city)])
								offset = offset + len(a)
							else:
								# print(lineno())
								offset = offset + 1
						else:
							# print(lineno())
							offset = offset + 1
				else:
					# print(lineno())
					offset = offset + 1
			for x in table:
				for y in x:
					y = str(y).encode("ASCII", "ignore")
			if len(table) > 3:
				with codecs.open("bytes.log", "a", encoding="utf-8") as f:
					f.write(("ID = %d\n"%packetID))
					print("ID = %d"%packetID)
					f.write(str(codecs.encode(bytes(copydata), "hex")))
					f.write("\n")
					f.write(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))
					print(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))
					f.write("---------------------------------\n")
				packetID += 1

if "Windows" in platform.platform():
	buff(data1)
else: 
	from scapy.all import *
	import resource
	sniff(filter="udp port 28960",prn=buff, store=0)

