import requests
import urllib3
import json
import sys
from tabulate import tabulate
import readline
from libs.headers.gen_header import *
import re

class CLI_Client:

    def __init__(self,teamserver_url:str,username:str,password:str,register:bool,register_key:str):
        self.teamserver_url = teamserver_url
        self.username = username
        self.password = password
        self.register = register
        self.register_key = register_key
        self.api_key = None
        self.ssl = "https" in self.teamserver_url
        self.headers = {'Content-Type': 'application/json','Accept': 'application/json',"X-Auth":""}
        urllib3.disable_warnings()


    def craft_and_send_get_request(self,request):
        try:
            if self.ssl:
                return requests.get(f"{self.teamserver_url}{request}",verify=False,headers=self.headers)
            else:
                return requests.get(f"{self.teamserver_url}{request}",headers=self.headers)
        except requests.exceptions.ConnectionError:
            print("[Error] Connectivity check failed")
        
    def craft_and_send_post_request(self,request,data):
        try:
            if self.ssl:
                return requests.post(f"{self.teamserver_url}{request}",verify=False,data=json.dumps(data),headers=self.headers)
            else:
                return requests.post(f"{self.teamserver_url}{request}",data=json.dumps(data),headers=self.headers)
        except requests.exceptions.ConnectionError:
            print("[Error] Connectivity check failed")
    
    def help(self,module):
        help_str = """
┌Help Panel─────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────────────────────────┐
│ \33[31mName\33[0m          │ \33[31mDescription\33[0m                                                                                              │ \33[31mUsage\33[0m                              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mlistener\33[0m      │ View Listeners                                                                                           │ listeners                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34moperators\33[0m     │ View all operators                                                                                       │ operators                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mvault\33[0m         │ Add/display credentials to/from the vault                                                                │ vault                              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mhelp\33[0m          │ Display the help menu for a command or in general                                                        │ help <command:optional>            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34minteract\33[0m      │ Interact with an agent                                                                                   │ interact <agent_name>              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34magents\33[0m        │ Show agents                                                                                              │ agents                             │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mmodules\33[0m       │ Show modules                                                                                             │ modules                            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mgenerate\33[0m      │ Generate payload using a template                                                                        │ generate                           │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mtemplates\33[0m     │ Show templates                                                                                           │ templates                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34musemodule\33[0m     │ Use an module                                                                                            │ usemodule <module name>            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mshellcode\33[0m     │ Show available shellcodes                                                                                │ shellcode                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mexit\33[0m          │ Quit the cli                                                                                             │ shellcode                          │
└───────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────────────────────────┘
"""
        if module==None:
            return help_str
        else:
            if module == "listener":
                help_dict = {"\33[31mOption\33[0m":["\33[34mstart\33[0m","\33[34mstop\33[0m","\33[34mrm\33[0m","\33[34mcreate\33[0m"],"\33[31mDescription\33[0m":["Start a listener with a given id","Stop a listener with a given id","Remove completely a listener","Create a listener (spawn a wizard)"],"\33[31mUsage\33[0m":["listener start <listener id>","listener stop <listener id>","listener rm <listener id>","listener create"]}
                return str(tabulate(help_dict, headers="keys", tablefmt="fancy_grid"))

    def cli_main_loop(self):
        while True:
            if not self.is_api_alive():
                print('\033[91m'+"[Error] Disconnected from teamserver"+ '\033[0m')
                break
            if not self.check_auth():
                self.authenticate()
            try:
                command = input('\033[92m'+"[LightC2]>"+ '\033[0m')
            except KeyboardInterrupt:
                print('\033[91m'+"\n[CTRL+C] Exiting !"+ '\033[0m')
                break
            if command == "exit":
                print('\033[91m'+"\n[Exit] Exiting the cli !"+ '\033[0m')
                if input('\033[91m'+"\nAre you sure you want to exit ? (y/n) :"+ '\033[0m').lower()=="y":
                    break
            elif command == "help":
                print(self.help(None))
            elif "help" in command and len(command.split(" "))>1 and command.split(" ")[1]!="":
                argument = command.split(" ")[1]
                print(self.help(argument))
            elif command == "operators":
                print(self.get_all_operators())
            elif "listener" in command:
                if command=="listener":
                    print(self.get_all_listeners())
                elif len(command.split(" "))>1 and command.split(" ")[1]!="":
                    if command.split(" ")[1]=="start" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_listener = command.split(" ")[2]
                        if self.start_listener(id_listener):
                            print('\033[92m'+f"\n[Success] Listener {id_listener} started !\n\033[0m")
                        else:
                            print(f"\033[31m\n[Error] Listener {id_listener} has not been started, check your arguments and the logs !\n\033[0m")
                    elif command.split(" ")[1]=="stop" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_listener = command.split(" ")[2]
                        if self.stop_listener(id_listener):
                            print('\033[92m'+f"\n[Success] Listener {id_listener} stopped !\n\033[0m")
                        else:
                            print(f"\033[31m\n[Error] Listener {id_listener} has not been stopped, check your arguments and the logs !\n\033[0m")
                    elif command.split(" ")[1]=="rm" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_listener = command.split(" ")[2]
                        if self.remove_listener(id_listener):
                            print('\033[92m'+f"\n[Success] Listener {id_listener} removed !\n\033[0m")
                        else:
                            print(f"\033[31m\n[Error] Listener {id_listener} has not been removed, check your arguments and the logs !\n\033[0m")
                    elif command.split(" ")[1]=="create":
                        print(gen_wizard())
                        try:
                            host = input("\033[31m[Wizard] Host > \033[0m")
                            port = input("\033[31m[Wizard] Port > \033[0m")
                            ssl = input("\033[31m[Wizard] SSL (y/n) > \033[0m").lower()
                            if ssl in ["y","n"] and re.match(r"^[0-9]+$",str(port)) and re.match(r"^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$",host):
                                ssl_bin = [0 if ssl=="n" else 1][0]
                                if self.add_listener(host,port,ssl_bin):
                                    print('\033[92m'+f"\n[Success] Listener {host}:{str(port)} successfully created\n\033[0m")
                                else:
                                    print(f"\033[31m\n[Error] Error creating listener {host}:{str(port)}, check the teamserver for more logs\n\033[0m")
                        except KeyboardInterrupt:
                            print("\n")
                            pass

    def is_api_alive(self):
        try:
            if self.ssl:
                return requests.get(f"{self.teamserver_url}/",verify=False).status_code==200
            else:
                return requests.get(f"{self.teamserver_url}/").status_code==200
        except requests.exceptions.ConnectionError:
            return False
    
    def check_auth(self):
        output = self.craft_and_send_get_request("/auth")
        if output.status_code == 200 and "[Success]" in output.content.decode():
            return True
        else:
            return False
    
    def authenticate(self)->bool:
        api_key = self.craft_and_send_post_request("/auth",{"username":self.username,"password":self.password})
        if not "[Error]" in api_key.content.decode() and api_key.status_code == 200:
            self.headers["X-Auth"]=api_key.content.decode()
            return True
        return False
    
    def register_user(self):
        if self.is_api_alive():
            output = requests.post(self.teamserver_url+"/register",data=json.dumps({"username":self.username,"password":self.password,"register_code":self.register_key}),headers=self.headers,verify=False)
            if output.status_code == 200 and "[Success]" in output.content.decode():
                return '\033[92m'+"[Success] User added !\033[0m"
            else:
                print(output.content.decode())
                return "\033[31m[Error] Error adding user !\033[0m"
        else:
            return "\033[31m[Error] Error adding user, Api is unreachable !\033[0m"


    def get_all_listeners(self)->str:
        listeners = self.craft_and_send_get_request("/listeners")
        if not "[Error]" in listeners.content.decode():
            all_listeners = listeners.json()['result']
            all_listeners_ordered = {'\033[31mid\033[0m':[],"\033[31mhost\033[0m":[],"\033[31mport\033[0m":[],"\033[31mssl\033[0m":[],"\033[31mactive\033[0m":[]}
            for listener in all_listeners:
                all_listeners_ordered["\033[31mid\033[0m"].append('\33[34m'+str(listener["host"])+":"+str(listener["port"])+"\033[0m")
                all_listeners_ordered["\033[31mhost\033[0m"].append(listener["host"])
                all_listeners_ordered["\033[31mport\033[0m"].append(listener["port"])
                all_listeners_ordered["\033[31mssl\033[0m"].append(listener["ssl"])
                all_listeners_ordered["\033[31mactive\033[0m"].append(listener["active"])
            return str(tabulate(all_listeners_ordered, headers="keys", tablefmt="fancy_grid"))
                
        return "\033[91m[Error] No result found !\033[0m"
    
    def start_listener(self, id):
        output = self.craft_and_send_post_request("/listeners/start",{"id":id})
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            return True
        return False
    
    def stop_listener(self,id):
        output = self.craft_and_send_post_request("/listeners/stop",{"id":id})
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            return True
        return False

    def remove_listener(self,id):
        output = self.craft_and_send_post_request("/listeners/rm",{"id":id})
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            return True
        return False
    
    def add_listener(self,host,port,ssl,admin_key=None,secret_key=None):
        data={"host":host,"port":port,"ssl":['1' if ssl else '0'][0]}
        if admin_key:
            data["admin_key"]=admin_key
        if secret_key:
            data["secret_key"]=secret_key
        output = self.craft_and_send_post_request("/listeners",data)
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            return True
        return False
    
    def get_all_operators(self):
        output = self.craft_and_send_get_request("/operators")
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            output_json = json.loads(output.content.decode())
            dict_data_ordered = {}
            for index,operator in enumerate(output_json["result"]):
                if not "\033[31mid\033[0m" in dict_data_ordered.keys():
                    dict_data_ordered["\033[31mid\033[0m"]=['\33[34m'+str(index)+"\033[0m"]
                else:
                    dict_data_ordered["\033[31mid\033[0m"].append('\33[34m'+str(index)+"\033[0m")
                if not "\033[31moperator\033[0m" in dict_data_ordered.keys():
                    dict_data_ordered["\033[31moperator\033[0m"]=[operator]
                else:
                    dict_data_ordered["\033[31moperator\033[0m"].append(operator)
            return str(tabulate(dict_data_ordered, headers="keys", tablefmt="fancy_grid"))

        return "\033[91m[Error] No result found !\033[0m"
    