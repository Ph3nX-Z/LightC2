from flask import Flask, request, render_template, redirect, send_from_directory, make_response, jsonify
import random,base64
from libs.utils.utils import *
from handlers.http_handler import *
from libs.utils.db_commands import *
import sqlite3
import re
import logging
import sys
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import base64
import datetime
from multiprocessing import Process
import json

class C2_Rest_API:


    def __init__(self,host:str|None=None,port:int|None=None,ssl:bool=True,register_code:str|None=None,db_path:str|None=None):
        self.host = host or "127.0.0.1"
        self.port = port or 8080
        self.ssl = ssl
        self.api = None
        self.all_listeners={}
        self.all_processes={}
        self.nonce = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
        self.encryption_key = get_random_bytes(32)
        self.register_code = register_code or base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
        self.db_path = db_path or "./libs/api/db/lightc2.db"
        ##### Methode stockage passwd : bcrypt
        ##### methode generation token : user : encrypted(heure+nonce+bcrypt+cheksum du token)  -> stockage en runtime dans un dico {"pseudo":{heure:token}} --> possibilité expiration token (par defaut qques heures) et 1 seul token valide a la fois (revoquer sessions via cli)
        ##### Voir pour de l'auth LDAP


    def init_api(self:object)->Flask:

        api = Flask(__name__)

        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR) # for dev only
        cli = sys.modules['flask.cli']
        cli.show_server_banner = lambda *x: None

        @api.route("/")
        def index():
            return "Welcome in LightC2's Rest API, check documentation for more informations"
        
        @api.route("/auth",methods=["POST"])
        def auth():
            data_from_post = request.json #curl -X POST https://127.0.0.1:8375/auth/ -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"data":"coucou"}' -k
            username = data_from_post["username"]
            password = data_from_post["password"]
            log_info(f"Trying to authenticate '{username}'","running")
            if re.match(r"^[a-z0-9_-]+$",username):
                hash = db_exec(check_user_in_db(username),self.db_path)
                if len(hash)!=0:
                    retained_hash = hash[0][0]
                    if verify_password(retained_hash,password,username):
                        log_info(f"Authenticated '{username}'","success")
                        now,nonce,token = self.gen_token(username)
                        log_info(f"Token generated and stored","success")
                        return token
                    else:
                        log_info(f"Failed to authenticate '{username}'","error")
                        return '[Error] Wrong Username or Password'
                else:
                    log_info(f"Failed to authenticate '{username}'","error")
                    return '[Error] Wrong Username or Password'
                
            else:
                log_info(f"Invalid Username Format","error")
                log_info(f"Failed to authenticate '{username}'","error")
                return "[Error] Invalid username format, please match the pattern : ^[a-z0-9_]+$"
    
        @api.route("/register",methods=["POST"])
        def register():
            data_from_post = request.json
            username = data_from_post["username"]
            password = data_from_post["password"]
            register_code = data_from_post["register_code"]
            log_info(f"Trying to register '{username}'","running")
            if register_code == self.register_code:
                username,hashed = hash_password(password,username)
                if re.match(r"^[a-z0-9_-]+$",username):
                    db_exec(add_user_to_db(username,hashed),self.db_path)
                    log_info(f"User Added to DB: '{username}'","success")
                    return "[Success] User successfully added !"
                else:
                    log_info(f"Invalid Username Format","error")
                    log_info(f"Failed to register '{username}'","error")
                    return "[Error] Invalid username format, please match the pattern : ^[a-z0-9_]+$"
            else:
                log_info("Invalid register code","error")
                log_info(f"Failed to register '{username}'","error")
                return "[Error] Bad register code, stop trying to hack into the teamserver !"
        
        @api.route("/operators",methods=["GET"])
        def operators():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            all_operators = db_exec(get_all_operators(),self.db_path)
            log_info(f"Providing a list of all operators to: '{username}'","success")
            return json.dumps(({"result":[operator[0] for operator in all_operators]}))
        
        @api.route("/listeners",methods=["GET","POST"])
        def listeners():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            if request.method == "GET":
                log_info(f"Providing list of listeners to '{username}'","running")
                listeners = db_exec(get_all_listeners(),self.db_path)
                output_json = {"result":[]}
                ordered_fields=["host","port","ssl","admin_key","secret_key",'active']
                for listener in listeners:
                    temp_dict={}
                    for index,value in enumerate(listener):
                        temp_dict[ordered_fields[index]] = str(value)
                    output_json["result"].append(temp_dict)
                log_info(f"Provided list of listeners to '{username}'","success")
                return json.dumps(output_json)
            
            elif request.method == "POST":
                data = request.json
                if not "host" in data.keys() or not "port" in data.keys() or not "ssl" in data.keys() or data["ssl"] not in [1,0,"1","0"]:
                    log_info(f"Missing fields in '{username}' request","error")
                    return "[Error] Please check the documentation to see the mandatory options"
                if not "admin_key" in data.keys():
                    admin_key = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
                else:
                    admin_key = data["admin_key"]
                if not "secret_key" in data.keys():
                    secret_key = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN") for _ in range(random.randint(25,30))]).encode())).decode()
                else:
                    secret_key = data["secret_key"]
                listener = HTTP_Handler(data["port"],data["host"],bool(int(data["ssl"])),False,admin_key,secret_key)
                self.all_listeners[f"{data['host']}:{data['port']}"]=listener
                if len(db_exec(check_if_listener_exists(data["port"]),self.db_path))==0:
                    db_exec(add_listener_to_db(data["host"],data["port"],str(data["ssl"]),0,secret_key,admin_key),self.db_path)
                    log_info(f"'{username}' successfully added a listener","success")
                    return "[Success] Successfully added listener"
                else:
                    log_info(f"'{username}' tried to add an existing listener","error")
                    return "[Error] Listener already exists with the given port" 

        @api.route("/listeners/start",methods=["POST"])
        def start_listener_api():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "id" in data.keys():
                log_info(f"Attempt to start a listener without providing id by '{username}'","error")
                return "[Error] please specify the identifier ('id':'host:port') of the listener to start"
            else:
                identifier = data["id"]
                if not re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+$",identifier):
                    log_info(f"Attempt to start a listener with invalid id provided by '{username}'","error")
                    return "[Error] Formating error, please use : host:port"
                if identifier in self.all_listeners.keys():
                    bind_port = self.all_listeners[identifier].port
                    if int(db_exec(is_listener_started(bind_port),self.db_path)[0][0])==1:
                        log_info(f"'{username}' Tried to start a listener that is already started","error")
                        return "[Error] Listener already started !"
                    log_info(f"'{username}' Starting listener {identifier}","running")
                    self.all_processes[identifier]=Process(target=self.all_listeners[identifier].start_listener)
                    self.all_processes[identifier].start()
                    db_exec(start_listener_update_db(bind_port),self.db_path)
                    log_info(f"Started listener {identifier} for {username}","success")
                    return "[Success] Listener Successfully started"
                else:
                    return "[Error] Non-Existent listener"
        
        @api.route("/listeners/stop",methods=["POST"])
        def stop_listener_api():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "id" in data.keys():
                log_info(f"Attempt to stop a listener without providing id by '{username}'","error")
                return "[Error] please specify the identifier ('id':'host:port') of the listener to stop"
            else:
                identifier = data["id"]
                if not re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+$",identifier):
                    log_info(f"Attempt to stop a listener with invalid id provided by '{username}'","error")
                    return "[Error] Formating error, please use : host:port"
                if identifier in self.all_listeners.keys():
                    bind_port = identifier.split(":")[1]
                    if int(db_exec(is_listener_started(bind_port),self.db_path)[0][0])==0:
                        log_info(f"'{username}' Tried to stop a listener that is already stopped","error")
                        return "[Error] Listener already stopped !"
                    log_info(f"'{username}' Stopping listener {identifier}","running")
                    self.all_listeners[identifier].stop_listener()
                    self.all_processes[identifier].terminate()
                    self.all_processes[identifier].join()
                    db_exec(stop_listener_update_db(bind_port),self.db_path)
                    log_info(f"Stopped listener {identifier} for {username}","success")
                    return "[Success] Listener Successfully stopped"
                else:
                    return "[Error] Non-Existent listener"


        self.api = api
        
    def start_api(self):
        log_info("Starting Rest API","running")
        if not self.api:
            self.init_api()
        self.generate_listeners_from_db()
        if self.ssl:
            self.api.run(host=self.host,port=self.port,ssl_context="adhoc",debug=False)
        else:
            self.api.run(host=self.host,port=self.port,debug=False)

    def vault():
        pass

    def modules():
        pass

    def generate_listeners_from_db(self)->None:
        log_info(f"Re-Generating listeners from db","running")
        listeners = db_exec(get_all_listeners(),self.db_path)
        output_json = {"result":[]}
        ordered_fields=["host","port","ssl","admin_key","secret_key",'active']
        for listener in listeners:
            temp_dict={}
            for index,value in enumerate(listener):
                temp_dict[ordered_fields[index]] = value
            output_json["result"].append(temp_dict)
        for listener in output_json["result"]:
            listener_object = HTTP_Handler(listener["port"],listener["host"],bool(int(listener["ssl"])),False,listener["admin_key"],listener["secret_key"])
            self.all_listeners[f"{listener['host']}:{listener['port']}"]=listener_object
            log_info(f"Listener {listener['host']}:{listener['port']} created","success")
        log_info(f"Re-Generated listeners from db","success")
        return None

    def gen_token(self,username:str)->tuple:
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nonce = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
        token = base64.b85encode(str(username + "<>" + nonce).encode()).decode()
        db_exec(set_token_for_user(now,username,hash,token,nonce),self.db_path)
        return now,nonce,token
    
    def verify_token(self,token:str)->bool:
        username = db_exec(get_user_from_token(token),self.db_path)
        return len(username)!=0 and base64.b85decode(token).decode().split("<>")[0]==username[0][0] and db_exec(get_token_from_username(username[0][0]),self.db_path)[0][0]==token



if __name__ == "__main__":
    api = C2_Rest_API()