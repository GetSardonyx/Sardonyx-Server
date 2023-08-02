import logging
from websocket_server import WebsocketServer
import json
import bcrypt
import os
import time
import uuid
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

basedir = os.getcwd()
connected = {
	"0": "Server"
}

uri = input("Database uri: ")
client = MongoClient(uri, server_api=ServerApi('1'))

# Configuration for MongoDB
datab = "Sardonyx" # The name of the main Database, default Sardonyx
posb = "Posts" # The name of the post collection, default Posts
usrb = "Users" # The name of the users colllection, default Users
# Configuration ends here

dba = client[datab]
posc = dba[posb]
usrc = dba[usrb]

class db:
	def insertPost(id, content, server):
		ts = time.time()
		datatosend = {
			"username": connected[str(id)],
			"content": content,
			"timestamp": ts,
			"likes": 0,
			"reports": []
		}
		try:
			posc.insert_one(datatosend)
		except:
			return "fail"
		server.send_message_to_all(str(datatosend))
		return "done"
		
	def authUser(username, password):
		acc = usrc.find_one({"username": username})
		if(acc!=None):
			if(acc["banned"]):
				return "banned"
			else:
				pw_hash = bytes(password, 'utf-8')
				hpw_hash = bytes(acc["password"], 'utf-8')
				if bcrypt.checkpw(pw_hash, hpw_hash):
					return "done"
				else:
					return "invalid"
		else:
			return "notmade"
		
	
	def insertUser(username, password):
		if(usrc.find_one({"username": username})==None):
			pw_hash = bytes(password, 'utf-8')
			hashed = bcrypt.hashpw(pw_hash, bcrypt.gensalt())
			hashdef = hashed.decode()
			datatosend = {
				"username": username,
				"password": hashdef,
				"banned": False,
				"bio": "This user has not set their bio.",
				"state": 0
			}
			try:
				usrc.insert_one(datatosend)
			except:
				return False
			return True
		else:
			return False
	
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
					if(db.insertUser(r["username"], r["password"])):
						loginclientwithid(client, r["username"], server)
					else:
						server.send_message(client, "803 - Signup Error")
				else:
					server.send_message(client, "702 - Malformed Data")
			else:
				server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="login"):
			if("username" in r):
				if("password" in r):
					auth = db.authUser(r["username"], r["password"])
					if(auth=="done"):
						loginclientwithid(client, r["username"], server)
					elif(auth=="invalid"):
						server.send_message(client, "704 - Invalid Password")	
					elif(auth=="banned"):
						server.send_message(client, "705 - Account Banned")	
					elif(auth=="notmade"):
						server.send_message(client, "703 - Invalid Username")
					else:
						server.send_message(client, "804 - Login Error")
				else:
					server.send_message(client, "702 - Malformed Data")
			else:
				server.send_message(client, "702 - Malformed Data")
		elif(r["ask"]=="post"):
			if("msg" in r):
				cltemp = client["id"]
				if(str(cltemp) in connected):
					stuff = db.insertPost(cltemp, r["msg"], server)
					if(stuff=="done"):
						server.send_message(client, "901 - OK")
					elif(stuff=="fail"):
						server.send_message(client, "805 - Posting Error")
					elif(stuff=="unauthed"):
						server.send_message(client, "602 - Unauthorized+")
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
