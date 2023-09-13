import flask
from flask import Flask, jsonify, request
from flask_restful import Resource, Api
import time
import json
import logging
from passlib.hash import scrypt
import os
import uuid
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import bson
import re
import secrets

hostip = "192.168.1.88" # set this to your computer's ip

app = Flask(__name__)
api = Api(app)

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
repb = "Reports" # The name of the reports colllection, default Reports
# Configuration ends here

dba = client[datab]
posc = dba[posb]
usrc = dba[usrb]
repc = dba[repb]

def parse_user(user, getPswd=False, getToken=False):
  if(user==None):
    return [False]
  else:
    resto = [True, user['username'], user['state'], user['restrictions']]
    resto.append(user['password']) if getPswd == True else False
    resto.append(user['token']) if getToken == True else False
    return resto

rep = {
  "ok": json.dumps({"Response": "OK"}),
  "inv": json.dumps({"Response": "Invalid"}),
  "exists": json.dumps({"Response": "Exists"}),
  "internal": json.dumps({"Response": "Internal"}),
  "nex": json.dumps({"Response": "NotExists"}),
  "state": json.dumps({"Response": "StateError"}),
}

class SignUp(Resource):
  def post(self):
    msg = request.get_json(force=True)
    if(usrc.find_one({"username": msg['username']})!=None):
      resp = flask.Response(rep['exists'], 500)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp
    hashdef = scrypt.hash(msg['password'])
    pid = str(uuid.uuid4())
    ts = time.time()
    try:
      datatosend = {
        "_id": pid,
        "created": ts,
        "username": msg['username'],
        "password": hashdef,
        "restrictions": [],
        "bio": "This user has not set their bio.",
        "token": secrets.token_hex(32),
        "ips": [request.headers['CF-Connecting-IP']],
        "state": 0
      }
    except:
      datatosend = {
        "_id": pid,
        "created": ts,
        "username": msg['username'],
        "password": hashdef,
        "restrictions": [],
        "bio": "This user has not set their bio.",
        "token": secrets.token_hex(32),
        "ips": ['unknown'],
        "state": 0
      }
    resp = flask.Response(rep['ok'], 201)
    try:
      usrc.insert_one(datatosend)
    except:
      resp = flask.Response(rep['internal'], 500)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

class GetToken(Resource):
  def post(self):
    msg = request.get_json(force=True)
    acc = usrc.find_one({"username": msg['username']})
    if(acc==None):
      resp = flask.Response(rep['nex'], 500)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp
    if(scrypt.verify(msg['password'], acc['password'])):
      resp = flask.Response(json.dumps({"Response": "OK", "Data": acc['token']}), 200)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp
    else:
      resp = flask.Response(rep['inv'], 400)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp

class DeleteAccount(Resource):
  def delete(self):
    msg = request.get_json(force=True)
    if "username" in msg:
      acc = usrc.find_one({"token": msg['token']})
      accp = parse_user(acc)
      if(accp[0]):
        if(accp[2]==2):
          resp = flask.Response(rep['ok'], 200)
          try:
            usrc.delete_one({"username": msg['username']})
          except:
            resp = flask.Response(rep['internal'], 500)
            resp.headers['Access-Control-Allow-Origin'] = '*'
            return resp
          resp.headers['Access-Control-Allow-Origin'] = '*'
          return resp
        resp = flask.Response(rep['state'], 400)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp
      else:
        resp = flask.Response(rep['nex'], 500)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp
    else:
      acc = usrc.find_one({"token": msg['token']})
      accp = parse_user(acc)
      if(accp[0]):
        resp = flask.Response(rep['ok'], 200)
        try:
          usrc.delete_one({"token": msg['token']})
        except:
          resp = flask.Response(rep['internal'], 500)
          resp.headers['Access-Control-Allow-Origin'] = '*'
          return resp
      else:
        resp = flask.Response(rep['nex'], 500)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp

class MakePost(Resource):
  def post(self):
    msg = request.get_json(force=True)
    acc = usrc.find_one({"token": msg['token']})
    accp = parse_user(acc)
    if(accp[0]):
      if("post" or "full" in accp[3]):
        resp = flask.Response(json.dumps({"Response": "Restricted", "Data": accp[3]}), 500)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp
      pid = str(uuid.uuid4())
      ts = time.time()
      datatosend = 
        "_id": pid,
        "username": accp[1],
        "content": msg['content'],
        "timestamp": ts,
        "likes": [],
        "comments": []
      }
    else:
      resp = flask.Response(rep['nex'], 500)
      resp.headers['Access-Control-Allow-Origin'] = '*'
      return resp
    resp = flask.Response(rep['ok'], 201)
    try:
      usrc.insert_one(datatosend)
    except:
      resp = flask.Response(rep['internal'], 500)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

api.add_resource(SignUp, '/0/account/register/', '/0/account/register')
api.add_resource(GetToken, '/0/account/token/', '/0/account/token')
api.add_resource(DeleteAccount, '/0/account/', '/0/account')

# driver function
if __name__ == '__main__':
  app.run(host=hostip, port=5000, debug=True, threaded=True)