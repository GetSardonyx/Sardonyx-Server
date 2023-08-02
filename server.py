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

if(os.path.isfile("./mongo.uri")):
	f = open("./mongo.uri", 'r')
	uri = f.readline().strip('\n')
	f.close()
else: 
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

class ws:
	def sendClient(client, msg):
		server.send_message(client, msg)
		
	def sendToAll(msg):
		server.send_message_to_all(msg)

class	db:
	def getUser(username):
		acc = usrc.find_one({"username": username})
		if(acc!=None):
			acc["password"] = ""
			return str(acc)
		else:
			return None
	
	def getPosts():
		return list(posc.find().sort("timestamp", -1).limit(10))
	
	def insertPost(id, content):
		ts = time.time()
		pid = str(uuid.uuid4())
		datatosend = {
			"_id": pid,
			"username": connected[str(id)],
			"content": content,
			"timestamp": ts,
			"likes": 0,
			"reports": []
		}
		try:
			posc.insert_one(datatosend)
		except Exception as e:
			print(e)
			return "fail"
		ws.sendToAll(str(datatosend))
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
			pid = str(uuid.uuid4())
			datatosend = {
				"_id": pid,
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
	
def loginclientwithid(client, username):
	cltemp = client["id"]
	connected[str(cltemp)] = username
	print("User " + username + " is now bound to connected ID " + str(cltemp))
	ws.sendClient(client, "902 - Bound")
	print(str(connected))

def new_client(client, server):
	ws.sendClient(client, str(client))
	
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
		ws.sendClient(client, "701 - Malformed Request")
	except:
		continuing = False
		ws.sendClient(client, "801 - Internal Confusion")
	if(continuing):
		if(not "ask" in r):
			ws.sendClient(client, "702 - Malformed Data")
		elif(r["ask"]=="signup"):
			if("username" in r):
				if("password" in r):
					if(db.insertUser(r["username"], r["password"])):
						loginclientwithid(client, r["username"])
					else:
						ws.sendClient(client, "803 - Signup Error")
				else:
					ws.sendClient(client, "702 - Malformed Data")
			else:
				ws.sendClient(client, "702 - Malformed Data")
		elif(r["ask"]=="login"):
			if("username" in r):
				if("password" in r):
					auth = db.authUser(r["username"], r["password"])
					if(auth=="done"):
						loginclientwithid(client, r["username"])
					elif(auth=="invalid"):
						ws.sendClient(client, "704 - Invalid Password")	
					elif(auth=="banned"):
						ws.sendClient(client, "705 - Account Banned")	
					elif(auth=="notmade"):
						ws.sendClient(client, "703 - Invalid Username")
					else:
						ws.sendClient(client, "804 - Login Error")
				else:
					ws.sendClient(client, "702 - Malformed Data")
			else:
				ws.sendClient(client, "702 - Malformed Data")
		elif(r["ask"]=="post"):
			if("msg" in r):
				cltemp = client["id"]
				if(str(cltemp) in connected):
					stuff = db.insertPost(cltemp, r["msg"])
					if(stuff=="done"):
						ws.sendClient(client, "901 - OK")
					elif(stuff=="fail"):
						ws.sendClient(client, "805 - Posting Error")
					elif(stuff=="unauthed"):
						ws.sendClient(client, "602 - Unauthorized")
				else:
					ws.sendClient(client, "602 - Unauthorized")
			else:
				ws.sendClient(client, "702 - Malformed Data")
		elif(r["ask"]=="ping"):
			ws.sendClient(client, "Pong!")
		elif(r["ask"]=="get_posts"):
			ws.sendClient(client, str(db.getPosts()))
		elif(r["ask"]=="get_user"):
			if("username" in r):
				ws.sendClient(client, str(db.getUser(r["username"])))
			else:
				ws.sendClient(client, "702 - Malformed Data")
		else:
			ws.sendClient(client, "000 - Invalid Data")
					
					

server = WebsocketServer(host='127.0.0.1', port=9001, loglevel=logging.INFO)
server.set_fn_new_client(new_client)
server.set_fn_message_received(on_msg)
server.set_fn_client_left(left_client)
server.run_forever()
