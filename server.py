import logging
from websocket_server import WebsocketServer
import json
import bcrypt
import os
import time
import uuid
import sqlite

basedir = os.getcwd()
connected = {
	"0": "Server"
}

class db:
	pass

class fdb:
	def createNewAccount(username, password):
		
	def loginToAccount(username, password):
	
	def createNewPost(msg, client):
	
	
	
	
	
	
	

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
					if(db.createNewAccount(r["username"], r["password"])):
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
					if(db.logIn(r["username"], r["password"])):
						loginclientwithid(client, r["username"], server)
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
					if(db.createNewPost(r["msg"], client):
						server.send_message(client, "901 - OK")
					else:
						server.send_message(client, "805 - Posting Error")
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
