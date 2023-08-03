import logging
from websocket_server import WebsocketServer
import json
import bcrypt
import os
import time
import uuid
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import bson

basedir = os.getcwd()

# dict that contains all connected clients and their client ids
connected = {
	"0": "Server"
}

# credits to Meower for this idea, all error codes and easy nicknames to refer to them
errors = {
	"ok": "901 - OK",
	"bound": "902 - Bound",
	"idk": "801 - Internal Confusion",
	"corrupt": "802 - Corrupted Account",
	"signup_error": "803 - Signup Error",
	"login_error": "804 - Login Error",
	"malformed_request": "701 - Malformed Request",
	"malformed": "702 - Malformed Data",
	"invalid_user": "703 - Invalid Username",
	"invalid_pass": "704 - Invalid Password",
	"banned": "705 - Account Banned",
	"exists": "601 - Exists",
	"unauthed": "602 - Unauthorized",
	"authed": "603 - Authorized",
	"state": "604 - Invalid State"
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

class	db: # database operations
	def changeUser(username, key, value): # change a user's account
		filter = { 'username': username }
		endr = { '$set': { key: value } }
		try:
			usrc.update_one(filter, endr)
		except Exception as e:
			print(e)
			return False
		return True
		
	def getUncleanedUser(username): # this returns a user's account without removing the password field, this should be used with heavy caution
		acc = usrc.find_one({"username": username})
		if(acc!=None):
			return acc
		else:
			return None

	def getUser(username): # this returns a user's account
		acc = usrc.find_one({"username": username})
		if(acc!=None):
			acc["password"] = "" # this replaces the password value with an empty string
			return acc
		else:
			return None
	
	def getPosts(): # gets 10 most recent posts
		return list(posc.find().sort("timestamp", -1).limit(10))
	
	def insertPost(id, content): # adds a post to the db and sends it to connected clients
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
		
	def authUser(username, password): # authenticates a user
		acc = usrc.find_one({"username": username})
		if(acc!=None):
			if(acc["banned"]):
				return "banned"
			else:
				pw_hash = bytes(password, 'utf-8')
				hpw_hash = bytes(acc["password"], 'utf-8')
				if bcrypt.checkpw(pw_hash, hpw_hash): # check if pswd is valid
					return "done"
				else:
					return "invalid"
		else:
			return "notmade"
		
	
	def insertUser(username, password): # inserts a new user account
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
	
def loginclientwithid(client, username): # binds client id and username
	cltemp = client["id"]
	connected[str(cltemp)] = username
	print("User " + username + " is now bound to connected ID " + str(cltemp))
	ws.sendClient(client, errors["bound"])
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
		ws.sendClient(client, errors["malformed_request"])
	except:
		continuing = False
		ws.sendClient(client, errors["idk"])
	if(continuing):
		if(not "ask" in r):
			ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="signup"):
			if("username" in r):
				if("password" in r):
					if(db.insertUser(r["username"], r["password"])):
						loginclientwithid(client, r["username"])
					else:
						ws.sendClient(client, errors["signup_error"])
				else:
					ws.sendClient(client, errors["malformed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="login"):
			if("username" in r):
				if("password" in r):
					auth = db.authUser(r["username"], r["password"])
					if(auth=="done"):
						loginclientwithid(client, r["username"])
					elif(auth=="invalid"):
						ws.sendClient(client, errors["invalid_pass"])	
					elif(auth=="banned"):
						ws.sendClient(client, errors["banned"])	
					elif(auth=="notmade"):
						ws.sendClient(client, errors["invalid_user"])
					else:
						ws.sendClient(client, errors["login_error"])
				else:
					ws.sendClient(client, errors["malformed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="post"):
			if("msg" in r):
				cltemp = str(client["id"])
				if(cltemp in connected):
					a = db.getUser(connected[cltemp])
					if(a==None):
						ws.sendClient(client, errors["corrupted"])
					elif(a["banned"]):
						ws.sendClient(client, errors["banned"])
					else:
						stuff = db.insertPost(cltemp, r["msg"])
						if(stuff=="done"):
							ws.sendClient(client, errors["ok"])
						elif(stuff=="fail"):
							ws.sendClient(client, errors["idk"])
						elif(stuff=="unauthed"):
							ws.sendClient(client, errors["unauthed"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="ping"):
			ws.sendClient(client, "Pong!")
		elif(r["ask"]=="get_posts"):
			ws.sendClient(client, str(db.getPosts()))
		elif(r["ask"]=="get_user"):
			if("username" in r):
				ws.sendClient(client, str(db.getUser(r["username"])))
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="ban"):
			if("username" in r):
				cltemp = str(client["id"])
				if(cltemp in connected):
					a = db.getUser(connected[cltemp])
					if(a["state"]!=0):
						ab = db.getUncleanedUser(r["username"])
						if(ab==None):
							ws.sendClient(client, errors["invalid_user"])
						else:
							ab["banned"] = True
							abc = db.changeUser(r["username"], "banned", True)
							if(abc):
								ws.sendClient(client, errors["ok"])
							else:
								ws.sendClient(client, errors["idk"])
					else:
						ws.sendClient(client, errors["state"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		else:
			ws.sendClient(client, errors["malformed_request"])
					
					

server = WebsocketServer(host='127.0.0.1', port=9001, loglevel=logging.INFO)
server.set_fn_new_client(new_client)
server.set_fn_message_received(on_msg)
server.set_fn_client_left(left_client)
server.run_forever()
