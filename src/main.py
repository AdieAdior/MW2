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
data1 = b'002438633041000eb629dda50800450000f4356000007f11f414a78e2b3f457bf93b7120712000e052b0ffffffff30706172747973746174650064604000840200000000000000002e0000000600000000000000000c0001ca9b33bd196fbe339bc0a80164a78e2b3f20712071000000000000000000000000000000000000000000000000000000000000000000000000000000004d62f7520000860100ffffffffffffff0a0000020000000001030000436f6d726164654563686f0000000000cefe8d0401001001c0a80164a78e2b3f20712071000000000000000000000000000000000000000000000000ff0889d82a8a08ff0a0000004509d0000000f20700'


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

def removecolour(string):
	if "Windows" in platform.platform():
		string = string.replace("^1", "")
		string = string.replace("^2", "")
		string = string.replace("^3", "")
		string = string.replace("^4", "")
		string = string.replace("^5", "")
		string = string.replace("^6", "")
		string = string.replace("^7", "")
		string = string.replace("^8", "")
		string = string.replace("^9", "")
		string = string.replace("^0", "")
		return string
	else:
		newstring = string.replace("^1",    "\x1b[1;31m")#red
		newstring = newstring.replace("^2", "\x1b[1;32m")#green
		newstring = newstring.replace("^3", "\x1b[1;33m")#yellow
		newstring = newstring.replace("^4", "\x1b[1;34m")#blue
		newstring = newstring.replace("^5", "\x1b[1;36m")#cyan
		newstring = newstring.replace("^6", "\x1b[1;35m")#pink
		newstring = newstring.replace("^7", "\x1b[1;37m")#white
		newstring = newstring.replace("^8", "\x1b[1;m")#black
		newstring = newstring.replace("^9", "\x1b[1;30m")#grey
		newstring = newstring.replace("^0", "\x1b[1;m")#black
		if string != newstring:
			return newstring + "\x1b[1;m"
		else:
			return string

def buff(data):
	try:
		main(data)
	except:
		pass

def main(data):
	# if data[IP].src != "167.142.43.63":
	copydata = data
	if 1 == 1:
		table = [["ID", "Name", "External IP", "Internal IP", "Steam ID", "P", "D", "R", "Pr", "VAC", "Hours", "Location"]]
		if "Windows" in platform.platform():
			data = codecs.decode(data, "hex")
		else:
			data = bytes(data)
		try:
			f.close()
		except:
			pass
		f = open('bytes.log', 'wb')
		f.write(data)
		data = data[42:]
		offset = 130
		if re.search(b"partystate", data) is not None:
			print("partystate")
			while offset + 83 < len(data):
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
							unpackedPacket[10],
							unpackedPacket[11],
							unpackedPacket[12]+1,
							unpackedPacket[13],
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
									unpackedPacket[10],
									unpackedPacket[11],
									unpackedPacket[12]+1,
									unpackedPacket[13],
									vacCheck(unpackedPacket[3],
									dec2ip(unpackedPacket[5])),
									gameCheck(unpackedPacket[3]),
									"%s, %s, %s" % (user.country, user.region, user.city)])
								offset = offset + len(a)
							else:
								offset = offset + 1
						else:
							offset = offset + 1
				else:
					offset = offset + 1
			for x in table:
				for y in x:
					y = str(y).encode("ASCII", "ignore")
			if len(table) > 3:
				if "Windows" not in platform.platform():
					print(copydata[IP].src)
				print(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))

if "Windows" in platform.platform():
	main(data1)
else: 
	from scapy.all import *
	import resource
	sniff(filter="udp port 28960",prn=buff, store=0)

