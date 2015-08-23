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

reader = geoip2.database.Reader("GeoLite2-City.mmdb")

class userLookup:
	city = country = region = location = ""
	def __init__(self, ip):
		self.ip = reader.city(ip)
		self.city = self.ip.city.name
		self.country = self.ip.country.name
		self.region = self.ip.subdivisions.most_specific.name
		self.location = "%s, %s, %s" % (self.city, self.region, self.country)


data1 = b'bc5ff4bb020b000eb629dda40800454803d84d3900006b1195bb4dab5921c0a801647120712003c40f28ffffffff307061727479737461746500ab4deb00880c00000000000000002e000000a054020000000000000c00086407c15ce77b5cc107c0a802064dab592120712071000000000000000000000000000000000000000000000000000000000000000000000000000000004db7a8510000860100ffffffffffffff0600000200000000f70780436f6d726164654563686f0000000000cefe8d0401001001c0a80164a78e2b3f20712071000000000000000000000000000000000000000000000000fbc0d848d6d8c0fb0000004509d900000005f9030001b1ff814f626977616e00000000004d8a560501001001c0a8b2185b217ac620712071000000000000000000000000000000000000000000000000efd799d1d299d7efe000000045023e0000002fea0040025c7f404773696c2f2f47614d33523435300000000000efae740c010010010593210105932101207120710000000000000000000000000000000000000000000000007dd3063e4c06d37d540000002001c1000000c424001003cf1f1044753a44000000000009c1df0a01001001c0a8b21f0592f8d8207120710000000000000000000000000000000000000000000000007dd3063e4c06d37d6d0000004504e3ffffff810700cc04e707465e324a654b69670000000000da87450e01001001c0a8b2365edb5ec020712071000000000000000000000000000000000000000000000000f23a64fd0a643af2000000450a29000000b494020005f37901736872696d707900000000002404db0b01001001c0a80004d56bb81a20712071000000000000000000000000000000000000000000000000b75aebd871ee5ab792000000450aefffffff20ed0040067c7da04f4d46470000000000a1e6ad0901001001c0a80066b2a4e193207120710000000000000000000000000000000000000000000000002c04ec5f63ec042c540000001b00b0ffffff0447001007df1e305661526b4b6945000000000044d80b08010010012996f0362996f03620712071000000000000000000000000000000000000000000000000943d9c5b5b9c3d94ee000000450a0c000000110e00e408ff0780496575616e0000000000423f550301001001c0a802064dab592120712071000000000000000000000000000000000000000000000000fbc0d848d6d8c0fb0000000800fdffffff4358020009f3bd81726f6c616e6463666f737465720000000000a6c52a0c01001001c0a80147c5582fbb207114da000000000000000000000000000000000000000000000000c495523c3c5295c4130000004500c0ffffff064701200a'



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
vac = {}
def vacCheck(steamID):
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
		for each in obj["response"]["games"]:
			if each["appid"] == 10190:
				hours[steamID]["data"] = int(each.get("playtime_forever")/60)
				hours[steamID]["time"] = time.time()
				return int(each.get("playtime_forever")/60)
	else:
		return hours.get(steamID).get("data")



def main():
	data = codecs.decode(data1, "hex")
	data = data[42:]
	offset = 130
	table = [["ID", "Name", "External IP", "Internal IP", "Steam ID", "Points", "Deaths", "Rank", "Presteige", "VAC", "Hours played", "Location"],]
	while offset + 80 < len(data):
		result = re.search(b'.+?\x00{24}......................',data[offset:] , re.DOTALL)
		a = result.group()
		length = len(a)
		nameLength = length - 75
		unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIxhbbbq'%nameLength, a)
		if sanityCheck(unpackedPacket):
			user = userLookup(str(dec2ip(unpackedPacket[5])))
			table.append([unpackedPacket[0], unpackedPacket[2], "%s:%d"%(dec2ip(unpackedPacket[5]),unpackedPacket[7]), "%s:%d"%(dec2ip(unpackedPacket[4]),unpackedPacket[6]), unpackedPacket[3], unpackedPacket[10], unpackedPacket[11], unpackedPacket[12], unpackedPacket[13], vacCheck(unpackedPacket[3]), gameCheck(unpackedPacket[3]), "%s, %s, %s" % (user.city, user.region, user.country)])
			offset = offset + length
		else:
			result = re.search(b'.+?\x00{24}.....................', data[offset:], re.DOTALL)
			a = result.group()
			length = len(a)
			nameLength = length - 74
			unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIhbbbq'%nameLength, a)
			if sanityCheck(unpackedPacket):
				user = userLookup(str(dec2ip(unpackedPacket[5])))
				table.append([unpackedPacket[0], unpackedPacket[2], "%s:%d"%(dec2ip(unpackedPacket[5]),unpackedPacket[7]), "%s:%d"%(dec2ip(unpackedPacket[4]),unpackedPacket[6]), unpackedPacket[3], unpackedPacket[10], unpackedPacket[11], unpackedPacket[12], unpackedPacket[13], vacCheck(unpackedPacket[3]), gameCheck(unpackedPacket[3]), "%s, %s, %s" % (user.city, user.region, user.country)])
				offset = offset + length
	print(tabulate(table, headers="firstrow"))

						





main()
print("first load done. repeat from cache")
main()
main()
main()


