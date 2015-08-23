from urllib import request
import json


def playerCheck(steamID):
	steamKey = open('steamAPI.txt').read()
	url = "http://api.steampowered.com/ISteamUser/GetPlayerBans/v1/?key=%s&steamids=%s"%(steamKey, steamID)
	req = request.urlopen(url)
	encoding = req.headers.get_content_charset()
	obj = json.loads(req.read().decode(encoding))
	if obj["players"][0]["VACBanned"] is False:
		return "False"
	else:
		return "%d VAC ban(s) %d days ago"%(obj["players"][0]["NumberOfVACBans"],obj["players"][0]["DaysSinceLastBan"])

def gameCheck(steamID):
	steamKey = open('steamAPI.txt').read()
	url = "http://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/?key=%s&steamid=%s&format=json"%(steamKey, steamID)
	req = request.urlopen(url)
	encoding = req.headers.get_content_charset()
	obj = json.loads(req.read().decode(encoding))
	for each in obj["response"]["games"]:
		if each["appid"] == 10190:
			return "%d/%d"%(int(each.get("playtime_forever")/60), int(each.get("playtime_2weeks")/60))
print(playerCheck(76561198069604145))
print(gameCheck(76561198069604145))
