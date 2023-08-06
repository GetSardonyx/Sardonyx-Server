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

# dict that contains all connected clients and their authed users
connected = {}

# dict that contains the timestamp of a clients last request
lc = {}

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
	"cl": "706 - Character Limit",
	"exists": "601 - Exists",
	"unauthed": "602 - Unauthorized",
	"authed": "603 - Authorized",
	"state": "604 - Invalid State",
	"ratelimit": "605 - Ratelimited"
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
# Configuration for development
debugMode = True # SET THIS TO FALSE IN PRODUCTION!! IF YOU LEAVE THIS AS TRUE THEN ALL INCOMING PACKETS WILL BE LOGGED, LEAKING SENSITIVE DATA!! LEAVE THIS OFF IN A PRODUCTION ENVIRONMENT!!
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
	def changePost(id, key, value): # change a post's data, e.g. liking or reporting
		filter = { '_id': id }
		endr = { '$set': { key: value } }
		try:
			posc.update_one(filter, endr)
		except Exception as e:
			print(e)
			return False
		return True

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
		if acc:
			return acc
		else:
			return None

	def getUser(username): # this returns a user's account
		acc = usrc.find_one({"username": username})
		if acc:
			acc["password"] = "REDACTED" # this replaces the password value with the string REDACTED
			return acc
		else:
			return None
			
	def getUncleanedPost(id): # this returns a post
		postv = posc.find_one({"_id": id})
		if postv:
			return postv
		else:
			return None
			
	def getPost(id): # this returns a post
		postv = posc.find_one({"_id": id})
		if postv:
			postv["reports"] = ["REDACTED"]
			return postv
		else:
			return None
	
	def getPosts(): # gets 10 most recent posts
		lis = list(posc.find().sort("timestamp", -1).limit(10))
		lis2 = []
		for x in lis:
			x["reports"] = ["REDACTED"]
			lis2.append(x)
		return lis2
	
	def insertPost(id, content): # adds a post to the db and sends it to connected clients
		if(len(content)<=312 and len(content)!=0):
			ts = time.time()
			pid = str(uuid.uuid4())
			datatosend = {
				"_id": pid,
				"username": id,
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
			ws.sendToAll(json.dumps(datatosend))
			return "done"
		else:
			return "cl"
		
	def authUser(username, password): # authenticates a user
		acc = usrc.find_one({"username": username})
		if acc:
			if(acc["banned"]):
				return "banned"
			else:
				if(len(username)<=14 and len(password)<=24 and len(username)>=3 and len(password)>=8):
					pw_hash = bytes(password, 'utf-8')
					hpw_hash = bytes(acc["password"], 'utf-8')
					if bcrypt.checkpw(pw_hash, hpw_hash): # check if pswd is valid
						return "done"
					else:
						return "invalid"
				else:
					return "cl"
		else:
			return "notmade"
		
	
	def insertUser(username, password): # inserts a new user account
		if(usrc.find_one({"username": username})==None):
			if(len(username)<=14 and len(password)<=24 and len(username)>=3 and len(password)>=8):
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
		else:
			return False
	
def loginclientwithid(client, username): # binds client id and username
	client["username"] = username
	connected[username] = client
	print("User " + username + " is now bound to connected ID " + str(client["id"]))
	ws.sendClient(client, errors["bound"])
	print(str(connected) + " //")

def new_client(client, server):
	ws.sendClient(client, str(client))
	
def left_client(client, server):
	if("username" in client):
		authin = client["username"]
		if str(authin) in connected:
			del connected[str(authin)]
			print(str(connected))
	if(str(client["id"]) in lc):
		del lc[str(client["id"])]
	
def on_msg(client, server, message):
	os.chdir(basedir)
	if(str(client["id"]) in lc):
		lca = lc[str(client["id"])]
		lcab = time.time() - lca
		if(lcab>=0.3):
			lc[str(client["id"])] = time.time()
		else:
			ws.sendClient(client, errors["ratelimit"])
			if debugMode:
				print("ID " + str(client["id"]) + " (ratelimited): " + str(message))
				
			return None
	else:
		lc[str(client["id"])] = time.time()
		print("added a client to the ratelimit // " + str(lc))
	if debugMode:
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
					if(not "username" in client):
						if(db.insertUser(r["username"], r["password"])):
							loginclientwithid(client, r["username"])
						else:
							ws.sendClient(client, errors["signup_error"])
					else:
						ws.sendClient(client, errors["authed"])
				else:
					ws.sendClient(client, errors["malformed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="login"):
			if("username" in r):
				if("password" in r):
					if(not "username" in client):
						auth = db.authUser(r["username"], r["password"])
						if(auth=="done"):
							loginclientwithid(client, r["username"])
						elif(auth=="invalid"):
							ws.sendClient(client, errors["invalid_pass"])	
						elif(auth=="banned"):
							ws.sendClient(client, errors["banned"])	
						elif(auth=="notmade"):
							ws.sendClient(client, errors["invalid_user"])
						elif(auth=="cl"):
							ws.sendClient(client, errors["cl"])
						else:
							ws.sendClient(client, errors["login_error"])
					else:
						ws.sendClient(client, errors["authed"])
				else:
					ws.sendClient(client, errors["malformed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="post"):
			if("msg" in r):
				if("username" in client):
					a = db.getUser(client["username"])
					if(a==None):
						ws.sendClient(client, errors["corrupted"])
					elif(a["banned"]):
						ws.sendClient(client, errors["banned"])
					else:
						stuff = db.insertPost(client["username"], r["msg"])
						if(stuff=="done"):
							ws.sendClient(client, errors["ok"])
						elif(stuff=="fail"):
							ws.sendClient(client, errors["idk"])
						elif(stuff=="unauthed"):
							ws.sendClient(client, errors["unauthed"])
						elif(stuff=="cl"):
							ws.sendClient(client, errors["cl"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="ping"):
			ws.sendClient(client, "Pong!")
		elif(r["ask"]=="get_posts"):
			if("username" in client):
				ws.sendClient(client, json.dumps(db.getPosts()))
			else:
				ws.sendClient(client, errors["unauthed"])
		elif(r["ask"]=="get_user"):
			if("username" in r):
				if("username" in client):
					user = db.getUser(r["username"])
					if user:
						ws.sendClient(client, json.dumps(user))
					else:
						ws.sendClient(client, "None")
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="ban"):
			if("username" in r):
				if("username" in client):
					a = db.getUser(client["username"])
					if(a["state"]!=0):
						ab = db.getUser(r["username"])
						if(ab==None):
							ws.sendClient(client, errors["invalid_user"])
						else:
							ab["banned"] = True
							abc = db.changeUser(r["username"], "banned", True)
							if(abc):
								try:
									abcd = connected[r["username"]]
									abcd["handler"].send_close(1000, bytes('', encoding='utf-8'))
								except:
									pass
								ws.sendClient(client, errors["ok"])
							else:
								ws.sendClient(client, errors["idk"])
					else:
						ws.sendClient(client, errors["state"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="kick"):
			if("username" in r):
				if("username" in client):
					a = db.getUser(client["username"])
					if(a["state"]!=0):
						try:
							abcd = connected[r["username"]]
							abcd["handler"].send_close(1000, bytes('', encoding='utf-8'))
						except:
							pass
						ws.sendClient(client, errors["ok"])
					else:
						ws.sendClient(client, errors["state"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="report_post"):
			if("id" in r and "reason" in r):
				if("username" in client):
					gp = db.getUncleanedPost(r["id"])
					if gp:
						try:
							ar = gp["reports"]
							ar.append(r["reason"])
							db.changePost(r["id"], "reports", ar)
							ws.sendClient(client, errors["ok"])
						except Exception as e:
							print(e)
							ws.sendClient(client, errors["idk"])
					else:
						ws.sendClient(client, errors["malformed"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="get_post"):
			if("id" in r):
				if("username" in client):
					gp = db.getPost(r["id"])
					if gp:
						ws.sendClient(client, json.dumps(gp))
					else:
						ws.sendClient(client, "None")
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="get_reports"):
			if("id" in r):
				if("username" in client):
					a = db.getUser(client["username"])
					if(a["state"]!=0):
						gp = db.getUncleanedPost(r["id"])
						if gp:
							ws.sendClient(client, json.dumps(gp["reports"]))
						else:
							ws.sendClient(client, errors["idk"])
					else:
						ws.sendClient(client, errors["state"])
				else:
					ws.sendClient(client, errors["unauthed"])
			else:
				ws.sendClient(client, errors["malformed"])
		elif(r["ask"]=="get_user_state"):
			if("username" in r):
				if("username" in client):
					dbr = db.getUser(r["username"])
					if dbr:
						ws.sendClient(client, json.dumps({"state": dbr["state"]}))
					else:
						ws.sendClient(client, errors["idk"])
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
