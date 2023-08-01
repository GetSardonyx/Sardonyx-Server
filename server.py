import logging
from websocket_server import WebsocketServer
import json
import bcrypt
import os
import time
import uuid

basedir = os.getcwd()
connected = {
	"0": "Server"
}

class Database:
	pass

def loginclientwithid(client, username, server):
	cltemp = client["id"]
	connected[str(cltemp)] = username
	print("User " + username + " is now bound to connected ID " + str(cltemp))
	server.send_message(client, "902 - Bound")
	print(str(connected))

def new_client(client, server):
	server.send_message(client, str(client))
	
def left_client(client, server):
	cltemp = client["id"]
	if str(cltemp) in connected:
		del connected[str(cltemp)]
		print(str(connected))
	
def on_msg(client, server, message):
	os.chdir(basedir)
	print("ID " + str(client["id"]) + ": " + str(message))
	continuing = True
	try:
		r = json.loads(str(message))
	except ValueError:
		continuing = False
		server.send_message(client, "701 - Malformed Request")
	except:
		continuing = False
		server.send_message(client, "801 - Internal Confusion")
	if(continuing):
		if(not "ask" in r):
			server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="makeacc"):
			if("username" in r):
				if("password" in r):
					isAccountMade = True
					os.chdir("./Users")
					try:
						f = open(f'{r["username"]}.json', "x")
					except FileExistsError:
						isAccountMade = False
						server.send_message(client, "601 - Exists")
					except:
						isAccountMade = False
						server.send_message(client, "801 - Internal Confusion")
					if(isAccountMade):
						try:
							ps_byte = bytes(r["password"], 'utf-8')
							hashed = bcrypt.hashpw(ps_byte, bcrypt.gensalt())
							hashdef = hashed.decode()
							f.write('{"username":"' + r["username"] + '","password":"' + hashdef + '","banned":"0","bio":"This user has not set their bio.","state":"0"}')
							f.close()
							loginclientwithid(client, r["username"], server)
						except:
							server.send_message(client, "801 - Internal Confusion")
				else:
					server.send_message(client, "702 - Malformed Data")
			else:
				server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="login"):
			if("username" in r):
				if("password" in r):
					os.chdir("./Users")
					if os.path.isfile("./" + r["username"] + ".json"):
						f = open(r["username"] + ".json")
						con3 = True
						try:
							s = json.load(f)
						except ValueError:
							con3 = False
							server.send_message(client, "802 - Corrupted Account Data")
						except:
							con3 = False
							server.send_message(client, "801 - Internal Confusion")
						if(con3):
							if("banned" in s):
								if("password" in s):
									if(s["banned"]=="0"):
										pw_bytes = bytes(r["password"], 'utf-8')
										hpw_bytes = bytes(s["password"], 'utf-8')
										if bcrypt.checkpw(pw_bytes, hpw_bytes):
											loginclientwithid(client, r["username"], server)
										else:
											server.send_message(client, "704 - Invalid Password")
									else:
										server.send_message(client, "705 - Account Banned")
								else:
									server.send_message(client, "802 - Corrupted Account Data")	
							else:
								server.send_message(client, "802 - Corrupted Account Data")
					else:
						server.send_message(client, "703 - Invalid Username")				
				else:
					server.send_message(client, "702 - Malformed Data")
			else:
				server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="post"):
			if("msg" in r):
				cltemp = client["id"]
				if(str(cltemp) in connected):
					os.chdir("./Posts")
					pid = uuid.uuid4()
					f = open(f'{}.json', "x")
					f.write('{"username":"' + connected[str(cltemp)] + '","content":"' + r["msg"] + '","timestamp":"' + str(time.time()) + '","id":"' + pid + '')
					f.close()
				else:
					server.send_message(client, "602 - Unauthorized")
			else:
				server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="ping"):
			server.send_message(client, "Pong!")
		else:
			server.send_message(client, "000 - No Specified Data")
					
					

server = WebsocketServer(host='127.0.0.1', port=9001, loglevel=logging.INFO)
server.set_fn_new_client(new_client)
server.set_fn_message_received(on_msg)
server.set_fn_client_left(left_client)
server.run_forever()
