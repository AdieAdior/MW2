from scapy.all import *
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
import subprocess

reader = geoip2.database.Reader("GeoLite2-City.mmdb")

class userLookup:
	city = country = region = location = ""
	def __init__(self, ip):
		try:
			self.ip = reader.city(ip)
			self.city = self.ip.city.name
			self.country = self.ip.country.name
			self.region = self.ip.subdivisions.most_specific.name
			self.location = "%s, %s, %s" % (self.city, self.region, self.country)
		except:
			self.location = "Unknown"


def sanityCheck(packet):
	if packet[10] >= 0:
		if packet[11] >= 0:
			if 0 <= packet[12] <= 69:
				if 0 <= packet[13] <= 11:
					return True
	return False

def dec2ip(ip):
	ip2 = struct.pack("<L", ip)
	return ipaddress.ip_address(ip2)

def colourReplace(string):
	newstring = string.replace("^1", "\033[1;31m")#red
	newstring = newstring.replace("^2", "\033[1;32m")#green
	newstring = newstring.replace("^3", "\033[1;33m")#yellow
	newstring = newstring.replace("^4", "\033[1;34m")#blue
	newstring = newstring.replace("^5", "\033[1;36m")#cyan
	newstring = newstring.replace("^6", "\033[1;35m")#pink
	newstring = newstring.replace("^7", "\033[1;37m")#white
	newstring = newstring.replace("^8", "\033[1;m")#black
	newstring = newstring.replace("^9", "\033[1;30m")#grey
	newstring = newstring.replace("^0", "\033[1;m")#black
	if string != newstring:
		return newstring + "\033[1;m"
	else:
		return string

def colourReplace(string):
	newstring = string.replace("^1", "\033[1;31m")#red
	newstring = newstring.replace("^2", "\033[1;32m")#green
	newstring = newstring.replace("^3", "\033[1;33m")#yellow
	newstring = newstring.replace("^4", "\033[1;34m")#blue
	newstring = newstring.replace("^5", "\033[1;36m")#cyan
	newstring = newstring.replace("^6", "\033[1;35m")#pink
	newstring = newstring.replace("^7", "\033[1;37m")#white
	newstring = newstring.replace("^8", "\033[1;m")#black
	newstring = newstring.replace("^9", "\033[1;30m")#grey
	newstring = newstring.replace("^0", "\033[1;m")#black
	if string != newstring:
		return newstring + "\033[1;m"
	else:
		return string

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
			print(subprocess.check_output(["easyrule block WAN %s"%ip], shell=True))
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
			else:
				print(url)
				return "private"
		else:
			print(url)
			return "private"
	else:
		return hours.get(steamID).get("data")



def customAction(data1):
	try:
		data = bytes(data1)
		data = data[42:]
		offset = 130
		if re.search(b"0partystate", data) is not None:
			table = [["ID", "Name", "External IP", "Internal IP", "Steam ID", "Points", "Deaths", "Rank", "Presteige", "VAC", "Hours played", "Location"],]
			while offset + 80 < len(data):
				result = re.search(b'.+?\x00{24}.{22}',data[offset:] , re.DOTALL)
				a = result.group()
				length = len(a)
				nameLength = length - 75
				unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIxhbbbq'%nameLength, a)
				if sanityCheck(unpackedPacket):
					user = userLookup(str(dec2ip(unpackedPacket[5])))
					table.append([unpackedPacket[0], unpackedPacket[2], dec2ip(unpackedPacket[5]), dec2ip(unpackedPacket[4]), unpackedPacket[3], unpackedPacket[10], unpackedPacket[11], unpackedPacket[12]+1, unpackedPacket[13], vacCheck(unpackedPacket[3],dec2ip(unpackedPacket[5])), gameCheck(unpackedPacket[3]), "%s, %s, %s" % (user.city, user.region, user.country)])
					offset = offset + length
				else:
					result = re.search(b'.+?\x00{24}.{21}', data[offset:], re.DOTALL)
					a = result.group()
					length = len(a)
					nameLength = length - 74
					unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIhbbbq'%nameLength, a)
					if sanityCheck(unpackedPacket):
						user = userLookup(str(dec2ip(unpackedPacket[5])))
						table.append([unpackedPacket[0], unpackedPacket[2], dec2ip(unpackedPacket[5]), dec2ip(unpackedPacket[4]), unpackedPacket[3], unpackedPacket[10], unpackedPacket[11], unpackedPacket[12]+1, unpackedPacket[13], vacCheck(unpackedPacket[3],dec2ip(unpackedPacket[5])), gameCheck(unpackedPacket[3]), "%s, %s, %s" % (user.city, user.region, user.country)])
						offset = offset + length
			for each1 in table:
				for each2 in each1:
					each = colourReplace(each)
			print(tabulate(table))
			#print(tabulate(table, headers="firstrow"))
	except Exception as e:
		print(e)
		print(data1)	



## Setup sniff, filtering for IP traffic
sniff(filter="udp port 28960",prn=customAction)
