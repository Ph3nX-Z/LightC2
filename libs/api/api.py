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
import hashlib
import urllib3

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
        urllib3.disable_warnings()
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
        
        @api.route("/auth",methods=["POST","GET"])
        def auth():
            if request.method == "POST":
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
            elif request.method == "GET":
                if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                    return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
                else:
                    return "[Success] You are authenticated !"
    
        @api.route("/register",methods=["POST"])
        def register():
            data_from_post = request.json
            if not "register_code" in data_from_post.keys() or not "username" in data_from_post.keys() or not "password" in data_from_post.keys():
                return "[Error] Please specify all the required fields !"
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
                listener = HTTP_Handler(data["port"],data["host"],bool(int(data["ssl"])),False,self.db_path,admin_key,secret_key)
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
                    if identifier in self.all_processes.keys():
                        self.all_processes[identifier].terminate()
                        self.all_processes[identifier].join()
                    db_exec(stop_listener_update_db(bind_port),self.db_path)
                    log_info(f"Stopped listener {identifier} for {username}","success")
                    return "[Success] Listener Successfully stopped"
                else:
                    return "[Error] Non-Existent listener"

        @api.route("/listeners/rm",methods=["POST"])
        def remove_listener():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "id" in data.keys():
                log_info(f"Attempt to rm a listener without providing id by '{username}'","error")
                return "[Error] please specify the identifier ('id':'host:port') of the listener to remove"
            else:
                identifier = data["id"]
                bind_port = identifier.split(":")[1]
                if not identifier in self.all_listeners.keys():
                    log_info(f"'{username}' Tried to remove an invalid listener {identifier}","error")
                    return "[Error] Tried to remove an invalid listener"
                if int(db_exec(is_listener_started(bind_port),self.db_path)[0][0])==1:
                    log_info(f"'{username}' Stopping listener {identifier}","running")
                    self.all_listeners[identifier].stop_listener()
                    if identifier in self.all_processes.keys():
                        self.all_processes[identifier].terminate()
                        self.all_processes[identifier].join()
                    db_exec(stop_listener_update_db(bind_port),self.db_path)
                    log_info(f"Stopped listener {identifier} for {username}","success")
                log_info(f"'{username}' Removing listener {identifier}","running")
                if identifier in self.all_processes.keys():
                    del(self.all_processes[identifier])
                del(self.all_listeners[identifier])
                db_exec(rm_listener_from_db(bind_port),self.db_path)
                log_info(f"Removed listener {identifier} for {username}","success")
                return "[Success] Listener Successfully stopped"

        @api.route("/vault",methods=["GET"])
        def get_vault():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Vault list asked by '{username}'","running")
            all_vaults = db_exec(get_all_vault_for_user(username),self.db_path)
            output_json = {"result":[]}
            for vault in all_vaults:
                output_json["result"].append(vault[0])
            log_info(f"Vault list provided to '{username}'","success")
            return json.dumps(output_json)
                
        @api.route("/vault/id",methods=["POST"])
        def get_vault_by_id():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Vault recuperation asked by '{username}'","running")
            data = request.json
            if not "password" in data.keys() or not "id" in data.keys():
                log_info(f"'{username}' tried to decrypt a vault without giving password","error")
                return "[Error] No password provided"
            password = data["password"]
            vault_id = data["id"]
            if not re.match(r"^[-A-Za-z0-9+]*={0,3}$",vault_id):
                log_info(f"'{username}' Tried to access a vault providing an invalid vault id","error")
                return "[Error] Vault id must be base64"
            unique_vault = db_exec(get_vault_for_user_and_id(username,vault_id),self.db_path)
            if len(unique_vault)==0:
                log_info(f"'{username}' Tried to access a vault that he's not owning","error")
                return "[Error] No vault retrieved"
            nonce = base64.b64decode(unique_vault[0][0])
            vault_content = base64.b64decode(unique_vault[0][1])
            m = hashlib.sha256()
            m.update(password.encode())
            hashed_password = m.digest()
            cipher = ChaCha20.new(key=hashed_password, nonce=nonce)
            plaintext = cipher.decrypt(vault_content)
            log_info(f"Vault provided to '{username}'","success")
            return plaintext


        @api.route("/vault/create",methods=["POST"])
        def create_vault():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Vault creation asked by '{username}'","running")
            data = request.json
            if not "password" in data.keys():
                log_info(f"'{username}' tried to create a vault without giving password","error")
                return "[Error] No password provided"
            password = data["password"]
            vault_data = {"vault_content":[]}
            vault_data = str(json.dumps(vault_data)).encode()
            m = hashlib.sha256()
            m.update(password.encode())
            hashed_password = m.digest()
            vault_id = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(10)]).encode())).decode()
            cipher = ChaCha20.new(key=hashed_password)
            log_info(f"'{username}' Encrypting vault with XChaCha20","running")
            ciphertext = cipher.encrypt(vault_data)
            log_info(f"Vault encrypted by '{username}'","success")
            nonce = base64.b64encode(cipher.nonce).decode("utf-8")
            ct = base64.b64encode(ciphertext).decode("utf-8")
            db_exec(add_encrypted_vault_to_db(username,nonce,vault_id,ct),self.db_path)
            log_info(f"Vault created by '{username}'","success")
            return "[Success] Vault created"



        @api.route("/vault/delete",methods=["POST"])
        def delete_vault():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Vault deletion initialised by '{username}'","running")
            data = request.json
            if not "id" in data.keys():
                return "[Error] Please provide a vault id"
            vault_id = data["id"]
            if not re.match(r"^[-A-Za-z0-9+]*={0,3}$",vault_id):
                log_info(f"Invalid vault id provided by '{username}'","error")
                return "[Error] Vault id must be base64"
            vault_user = db_exec(get_username_by_vault_id(vault_id),self.db_path)
            if len(vault_user)==0:
                log_info(f"Invalid vault id provided by '{username}'","error")
                return "[Error] Invalid vault id provided, non-existant"
            else:
                vault_user = vault_user[0][0]
            if vault_user==username:
                db_exec(del_vault_from_id(vault_id),self.db_path)
                log_info(f"Vault {vault_id} deleted by '{username}'","success")
                return "[Success] Vault deleted"
            else:
                log_info(f"'{username}' Tried to delete a vault which he's not owning","error")
                return "[Error] You are not authorized to access this vault"

        @api.route("/vault/add",methods=["POST"])
        def add_entry_vault():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"'{username}' Adding entry to vault","running")
            data = request.json
            if not "password" in data.keys() or not "id" in data.keys() or not "password_add" in data.keys() or not 'username_add' in data.keys():
                log_info(f"'{username}' tried to add an entry to a vault without giving password/id/data to add","error")
                return "[Error] No password/id/data provided"
            password = data["password"]
            vault_id = data["id"]
            password_to_add = data["password_add"]
            username_to_add = data["username_add"]
            if not re.match(r"^[-A-Za-z0-9+]*={0,3}$",vault_id):
                return "[Error] Vault id must be base64"
            unique_vault = db_exec(get_vault_for_user_and_id(username,vault_id),self.db_path)
            if len(unique_vault)==0:
                log_info(f"'{username}' asked for an invalid vault","error")
                return "[Error] No vault retrieved"
            nonce = base64.b64decode(unique_vault[0][0])
            vault_content = base64.b64decode(unique_vault[0][1])
            m = hashlib.sha256()
            m.update(password.encode())
            hashed_password = m.digest()
            cipher = ChaCha20.new(key=hashed_password, nonce=nonce)
            plaintext = cipher.decrypt(vault_content)
            try:
                dict_vault = json.loads(plaintext)
            except json.decoder.JSONDecodeError:
                log_info(f"'{username}' got an error decrypting the vault (password/corrupted base)","error")
                return '[Error] Error while decrypting the vault, maybe the password is wrong or the vault is corrupted'
            dict_vault["vault_content"].append((str(username_to_add),str(password_to_add)))
            vault_data = str(json.dumps(dict_vault)).encode()
            cipher_enc = ChaCha20.new(key=hashed_password, nonce=nonce)
            ciphertext = cipher_enc.encrypt(vault_data)
            ct = base64.b64encode(ciphertext).decode("utf-8")
            db_exec(change_vault_blob(vault_id,ct),self.db_path)
            log_info(f"'{username}' Successfully added cred to vault","success")
            return "[Success] Creds added to vault blob"

        @api.route("/vault/remove",methods=["POST"])
        def remove_entry_vault():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"'{username}' Removing entry from vault","running")
            data = request.json
            if not "password" in data.keys() or not "id" in data.keys() or not "cred_index" in data.keys():
                log_info(f"'{username}' tried to remove an entry from a vault without giving password/id/cred index","error")
                return "[Error] No password/id/cred index provided"
            password = data["password"]
            vault_id = data["id"]
            cred_index = data["cred_index"]
            if not re.match(r"^[-A-Za-z0-9+]*={0,3}$",vault_id):
                return "[Error] Vault id must be base64"
            unique_vault = db_exec(get_vault_for_user_and_id(username,vault_id),self.db_path)
            if len(unique_vault)==0:
                log_info(f"'{username}' asked for an invalid vault","error")
                return "[Error] No vault retrieved"
            nonce = base64.b64decode(unique_vault[0][0])
            vault_content = base64.b64decode(unique_vault[0][1])
            m = hashlib.sha256()
            m.update(password.encode())
            hashed_password = m.digest()
            cipher = ChaCha20.new(key=hashed_password, nonce=nonce)
            plaintext = cipher.decrypt(vault_content)
            try:
                dict_vault = json.loads(plaintext)
            except json.decoder.JSONDecodeError:
                log_info(f"'{username}' got an error decrypting the vault (password/corrupted base)","error")
                return '[Error] Error while decrypting the vault, maybe the password is wrong or the vault is corrupted'
            try:
                dict_vault["vault_content"].pop(int(cred_index))
            except:
                log_info(f"'{username}' entered an invalid index number","error")
                return "[Error] Index is not a number or is greater than the size of the vault"
            vault_data = str(json.dumps(dict_vault)).encode()
            cipher_enc = ChaCha20.new(key=hashed_password, nonce=nonce)
            ciphertext = cipher_enc.encrypt(vault_data)
            ct = base64.b64encode(ciphertext).decode("utf-8")
            db_exec(change_vault_blob(vault_id,ct),self.db_path)
            log_info(f"'{username}' Successfully removed cred from vault","success")
            return "[Success] Creds removed from the vault blob"

        @api.route("/agents",methods=["GET"])
        def get_agents():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"'{username}' asked for the agent list","running")
            all_agents = {}
            for listener_id in self.all_listeners.keys():
                listener = self.all_listeners[listener_id]
                if listener_id in self.all_processes.keys():
                    admin_key = listener.admin_key
                    port = listener.port
                    host = listener.host
                    ssl = listener.ssl
                    url = f'http{["s" if ssl else ""][0]}://{host}:{port}/get_agents'
                    headers = {"X-Auth":admin_key,"Accept":"application/json","Content-Type":"application/json"}
                    all_listener_agents = requests.get(url,headers=headers,verify=False).json()
                    all_agents[f"{listener.host}:{listener.port}"]=all_listener_agents
            log_info(f"Agent list provided to '{username}'","success")
            return json.dumps({"result":all_agents})
        
        @api.route("/agents/exec",methods=["POST"])
        def exec_method_agent():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "agent_id" in data.keys() or not "method" in data.keys() or not "arguments" in data.keys():
                return "[Error] Please provide all the required fields"
            agent_id = data["agent_id"]
            method = data["method"]
            arguments = data["arguments"]
            if not re.match(r"^[a-zA-Z0-9]+$",agent_id) or not re.match(r"^[a-z0-9A-Z_]+$",method):
                return "[Error] Some fields contain invalid data"
            arguments = base64.b64encode(arguments.encode()).decode()
            db_exec(add_job_to_db(agent_id,method,arguments),self.db_path)
            return "[Success] Job added to db"
        
        @api.route("/jobs",methods=["GET"])
        def get_jobs():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Giving all running jobs to {username}","running")
            all_jobs = db_exec(get_jobs_running(),self.db_path)
            jobs_dict = {}
            all_agents = {}
            for listener_id in self.all_listeners.keys():
                listener = self.all_listeners[listener_id]
                if listener_id in self.all_processes.keys():
                    admin_key = listener.admin_key
                    port = listener.port
                    host = listener.host
                    ssl = listener.ssl
                    url = f'http{["s" if ssl else ""][0]}://{host}:{port}/get_agents'
                    headers = {"X-Auth":admin_key,"Accept":"application/json","Content-Type":"application/json"}
                    all_listener_agents = requests.get(url,headers=headers,verify=False).json()
                    for agent in all_listener_agents.keys():
                        all_agents[agent]=all_listener_agents[agent]["name"]
            for job in all_jobs:
                if job[1] in all_agents.keys():
                    agent_name = all_agents[job[1]]
                else:
                    agent_name = "Unknown"
                jobs_dict[job[0]]={"agent":agent_name,"agent_id":job[1],"module":job[2],"argument":job[3],"output":job[4],"date_started":job[5],"status":job[6],"displayed":job[7]}
            log_info(f"All running jobs given to {username}","success")
            return jobs_dict
        
        @api.route("/jobs/all",methods=["GET"])
        def get_jobs_all_api():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Giving all the jobs to {username}","running")
            all_jobs = db_exec(get_jobs_all(),self.db_path)
            jobs_dict = {}
            all_agents = {}
            for listener_id in self.all_listeners.keys():
                listener = self.all_listeners[listener_id]
                if listener_id in self.all_processes.keys():
                    admin_key = listener.admin_key
                    port = listener.port
                    host = listener.host
                    ssl = listener.ssl
                    url = f'http{["s" if ssl else ""][0]}://{host}:{port}/get_agents'
                    headers = {"X-Auth":admin_key,"Accept":"application/json","Content-Type":"application/json"}
                    all_listener_agents = requests.get(url,headers=headers,verify=False).json()
                    for agent in all_listener_agents.keys():
                        all_agents[agent]=all_listener_agents[agent]["name"]
            for job in all_jobs:
                if job[1] in all_agents.keys():
                    agent_name = all_agents[job[1]]
                else:
                    agent_name = "Unknown"
                jobs_dict[job[0]]={"agent":agent_name,"agent_id":job[1],"module":job[2],"argument":job[3],"output":job[4],"date_started":job[5],"status":job[6],"displayed":job[7]}
            log_info(f"All jobs given to {username}","success")
            return jobs_dict
        
        @api.route("/jobs/tasked",methods=["GET"])
        def get_jobs_tasked_api():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            log_info(f"Giving all the jobs to {username}","running")
            all_jobs = db_exec(get_jobs_tasked(),self.db_path)
            jobs_dict = {}
            all_agents = {}
            for listener_id in self.all_listeners.keys():
                listener = self.all_listeners[listener_id]
                if listener_id in self.all_processes.keys():
                    admin_key = listener.admin_key
                    port = listener.port
                    host = listener.host
                    ssl = listener.ssl
                    url = f'http{["s" if ssl else ""][0]}://{host}:{port}/get_agents'
                    headers = {"X-Auth":admin_key,"Accept":"application/json","Content-Type":"application/json"}
                    all_listener_agents = requests.get(url,headers=headers,verify=False).json()
                    for agent in all_listener_agents.keys():
                        all_agents[agent]=all_listener_agents[agent]["name"]
            for job in all_jobs:
                if job[1] in all_agents.keys():
                    agent_name = all_agents[job[1]]
                else:
                    agent_name = "Unknown"
                jobs_dict[job[0]]={"agent":agent_name,"agent_id":job[1],"module":job[2],"argument":job[3],"output":job[4],"date_started":job[5],"status":job[6]}
            log_info(f"All jobs given to {username}","success")
            return jobs_dict
        
        @api.route("/jobs/review",methods=["POST"])
        def review_job():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "id" in data.keys():
                return "[Error] Please provide all the required fields"
            db_exec(set_job_reviewed(data["id"]),self.db_path)
            return ""
        
        @api.route("/jobs/id",methods=["POST"])
        def get_jobs_byid_api():
            if not "X-Auth" in request.headers.keys() or not self.verify_token(request.headers["X-Auth"]):
                log_info("Someone tried to access a webpage without being authenticated/giving a good password","error")
                return "[Error] Please provide an API Key via X-Auth or correct the one you gave"
            else:
                username = db_exec(get_user_from_token(request.headers["X-Auth"]),self.db_path)[0][0]
            data = request.json
            if not "job_id" in data.keys():
                return "[Error] Please provide all the required fields"
            job = db_exec(get_job_by_jobid(data["job_id"]),self.db_path)
            if len(job)==0:
                return "[Error] No such job"
            job = job[0]
            job_dict = {"job_id":job[0],"agent_id":job[1],"module":job[2],"argument":job[3],"output":job[4],"date_started":job[5],"status":job[6]}
            return json.dumps(job_dict)
            
            


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
            listener_object = HTTP_Handler(listener["port"],listener["host"],bool(int(listener["ssl"])),False,self.db_path,listener["admin_key"],listener["secret_key"])
            self.all_listeners[f"{listener['host']}:{listener['port']}"]=listener_object
            log_info(f"Listener {listener['host']}:{listener['port']} created","success")
            if int(listener["active"])==1:
                bind_port = listener_object.port
                log_info(f"Starting listener {listener['host']}:{listener['port']}","running")
                self.all_processes[f"{listener['host']}:{listener['port']}"]=Process(target=self.all_listeners[f"{listener['host']}:{listener['port']}"].start_listener)
                self.all_processes[f"{listener['host']}:{listener['port']}"].start()
                db_exec(start_listener_update_db(bind_port),self.db_path)
                log_info(f"Started listener {listener['host']}:{listener['port']}","success")

        log_info(f"Re-Generated listeners from db","success")
        return None

    def gen_token(self,username:str)->tuple:
        previous_token = db_exec(get_token_from_username_full(username),self.db_path)
        if len(previous_token)!=0:
            date_generated_last = previous_token[0][3]
            nonce_previous = previous_token[0][4]
            token_previous = previous_token[0][2]
            now = datetime.datetime.now()
            nonce = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
            token = base64.b85encode(str(username + "<>" + nonce).encode()).decode()
            if  now - datetime.datetime.strptime(date_generated_last, "%Y-%m-%d %H:%M:%S") > datetime.timedelta(minutes=20):
                db_exec(set_token_for_user(now.strftime("%Y-%m-%d %H:%M:%S"),username,"",token,nonce),self.db_path)
                return now.strftime("%Y-%m-%d %H:%M:%S"),nonce,token
            else:
                return date_generated_last,nonce_previous,token_previous
        else:
            now = datetime.datetime.now()
            nonce = base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
            token = base64.b85encode(str(username + "<>" + nonce).encode()).decode()
            db_exec(set_token_for_user(now.strftime("%Y-%m-%d %H:%M:%S"),username,"",token,nonce),self.db_path)
            return now.strftime("%Y-%m-%d %H:%M:%S"),nonce,token
    
    def verify_token(self,token:str)->bool:
        if token!="":
            username = db_exec(get_user_from_token(token),self.db_path)
            creation_time = db_exec(get_datetime_from_token(token),self.db_path)[0][0]
            date_object = datetime.datetime.strptime(creation_time, "%Y-%m-%d %H:%M:%S")
            current_time = datetime.datetime.now()
            time_difference = current_time - date_object
            fifteen_minutes = datetime.timedelta(minutes=20)
            if time_difference > fifteen_minutes:
                return False
            return len(username)!=0 and base64.b85decode(token).decode().split("<>")[0]==username[0][0] and db_exec(get_token_from_username(username[0][0]),self.db_path)[0][0]==token
        else:
            return False



if __name__ == "__main__":
    api = C2_Rest_API()