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


data1 = b"\xff\xff\xff\xff0partystate\x00Oma\x00\xa4\t\x00\x00\x00\x00\x00\x00\x00\x00.\x00\x00\x00\x84\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\xc4U\xb27Q\xc7\x19E\xde\xc0\xa8\x00dd\x04{_ q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00~\xc8\x04R\x00\x00\x86\x01\x00\xff\xff\xff\xff\xff\xff\xff\x0b\x00\x00\x02\x00\x00\x00\x00\xef\x00\x80\xce\xbb(Fedora) Duck-Life\xce\xbb\x00\x00\x00\x00\x00\x05\x80M\x04\x01\x00\x10\x01\xc0\xa8\x00dd\x04{_ q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00*\xed@\xd7\xf8@\xed*\x00\x00\x00E\x02\x89\xff\xff\xffo\x80\x04\x00\x01\xb1;\x80VintageVanGogh\x00\x00\x00\x00\x00=\xcc\x8b\t\x01\x00\x10\x01\x80\xb4k\x88\x80\xb4k\x88 q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\xdcJ|\xbdJ\xdc'\x90\x00\x00\x00E\x00n\xff\xff\xff H\x01@\x02\xdc\x0e@Cornie\x00\x00\x00\x00\x00\xe2\x9d\x0e\x08\x01\x00\x10\x01\xc0\xa8\x01\x93H'\xa2q q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x80Q\x1bFQ\x80@(\x00\x00\x00\x03\x00\xe3\xff\xff\xff@\x00\x00\x90\x03\xbf\x03\x18McBack\x00\x00\x00\x00\x00@\xb3\x13\x03\x01\x00\x10\x01\xc0\xa8\x01\x03\xd8\xc5\xb9I q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x0e\x86\r\x17\x86\x0e\xc6\xd9\x00\x00\x00E\x01\xc5\x00\x00\x00\x82\x00\x00\xcc\x04\xe7\x00HChichiflan\x00\x00\x00\x00\x00~\xfe\xd1\x0c\x01\x00\x10\x01\xc0\xa8\x00\x04\xb5\x1c\xb9\xf2 q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00v!\xe4P\x87\xe4!v\x00\x00\x00\x0f\x00l\xff\xff\xff\x18\xb0\x04\x00\x053\x00\x00ComradeEcho\x00\x00\x00\x00\x00\xce\xfe\x8d\x04\x01\x00\x10\x01\xc0\xa8\x01k\xa7\x8e+? q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xfc\xd2\xdd\xdd\xd2\xfc\xfe`\x00\x00\x00E\t\xd1\x00\x00\x00A\xfe\x00@\x06\xfc\x0c\xa0Bilford Wrimbley\x00\x00\x00\x00\x00\x0c\xc5\xfc\x02\x01\x00\x10\x01K\x8f\xd6rK\x8f\xd6r q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf3:]\xb5\xb9^:\xf3D\x00\x00\x00E\x00\x80\xff\xff\xffBJ\x000\x07\xbf\x020ElloImOise\x00\x00\x00\x00\x00\x14\xaa&\x08\x01\x00\x10\x01\xc0\xa8\x01\x07bnp~ q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcf\xe3\xfcu\x83\xfc\xe3\xcf\n\x00\x00\x00\x04\x00\x02\x00\x00\x00\x00\x00\x00\xcc\x08o\x00\x8cDaniyull\x00\x00\x00\x00\x00\x86\x94&\x08\x01\x00\x10\x01\xc0\xa8\x01\x0bl#\n\x9b q q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcf\xe3\xfcu\x83\xfc\xe3\xcf\x00\x00\x00\x07\x00t\x00\x00\x00\x00\x04\x00\x00"



print(codecs.encode(data1, "hex"))


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
	#data = codecs.decode(data1, "hex")
	data = data1[42:]
	offset = 130
	table = [["ID", "Name", "External IP", "Internal IP", "Steam ID", "Points", "Deaths", "Rank", "Presteige", "VAC", "Hours played", "Location"],]
	while offset + 80 < len(data):
		print(data[offset:])
		print()
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
			print(data[offset:])
			print()
			result = re.search(b'.+?\x00{24}.....................', data[offset:], re.DOTALL)
			a = result.group()
			length = len(a)
			nameLength = length - 74
			unpackedPacket = struct.unpack('<b3s%ds5xqIIhh24xIIhbbbq'%nameLength, a)
			if sanityCheck(unpackedPacket):
				user = userLookup(str(dec2ip(unpackedPacket[5])))
				table.append([unpackedPacket[0], unpackedPacket[2], "%s:%d"%(dec2ip(unpackedPacket[5]),unpackedPacket[7]), "%s:%d"%(dec2ip(unpackedPacket[4]),unpackedPacket[6]), unpackedPacket[3], unpackedPacket[10], unpackedPacket[11], unpackedPacket[12], unpackedPacket[13], vacCheck(unpackedPacket[3]), gameCheck(unpackedPacket[3]), "%s, %s, %s" % (user.city, user.region, user.country)])
				offset = offset + length
	print(tabulate(table))
	print(tabulate(table, headers="firstrow"))

						





main()



