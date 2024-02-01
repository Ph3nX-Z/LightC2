import requests
import urllib3
import json
import sys
from tabulate import tabulate
import readline
from libs.headers.gen_header import *
import re
import datetime
import base64

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
│ \33[34mlistener\33[0m      │ Manage listeners (help for more informations)                                                            │ listeners                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mjobs\33[0m          │ Manage jobs (help for more informations)                                                                 │ jobs                               │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34moperators\33[0m     │ View all operators                                                                                       │ operators                          │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mvault\33[0m         │ Manage vaults (help for more informations)                                                               │ vault                              │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34mhelp\33[0m          │ Display the help menu for a command or in general                                                        │ help <command:optional>            │
├───────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────────────────────────┤
│ \33[34magents\33[0m        │ Manage agents (help for more informations)                                                               │ agents                             │
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
                help_dict = {"\33[31mOption\33[0m":["\33[34mlistener\33[0m","\33[34mstart\33[0m","\33[34mstop\33[0m","\33[34mrm\33[0m","\33[34mcreate\33[0m"],"\33[31mDescription\33[0m":["Enumerate listeners","Start a listener with a given id","Stop a listener with a given id","Remove completely a listener","Create a listener (spawn a wizard)"],"\33[31mUsage\33[0m":["listener","listener start <listener id>","listener stop <listener id>","listener rm <listener id>","listener create"]}
            elif module == "vault":
                help_dict = {"\33[31mOption\33[0m":["\33[34mvault\33[0m","\33[34mget\33[0m","\33[34mcreate\33[0m","\33[34mdelete\33[0m","\33[34mrm\33[0m","\33[34madd\33[0m"],"\33[31mDescription\33[0m":["Enumerate vaults for your user","Get the content of a vault","Create a vault","Delete completely a vault","Remove an entry from the vault with its index","Add an entry to the vault"],"\33[31mUsage\33[0m":["vault","vault get <vault id>","vault create","vault delete <vault id>","vault rm <vault id> <cred index>","vault add <vauld id> <username> <password>"]}
            elif module=="agents":
                help_dict = {"\33[31mOption\33[0m":["\33[34magents\33[0m","\33[34minteract\33[0m","\33[34mremove_stale\33[0m"],"\33[31mDescription\33[0m":["Get all the agents","Interact with an agent","Remove unresponsive agents"],"\33[31mUsage\33[0m":["agents","agents interact <agent id>","agents remove_stale"]}
            elif module == "jobs":
                help_dict = {"\33[31mOption\33[0m":["\33[34mjobs\33[0m","\33[34mall\33[0m","\33[34mrunning\33[0m","\33[34mtasked\33[0m","\33[34mget\33[0m"],"\33[31mDescription\33[0m":["Get all the running jobs only","Get all jobs","Get only running jobs","Get only tasked jobs","Get a job by id"],"\33[31mUsage\33[0m":["jobs","jobs all","jobs running","jobs tasked","jobs get <job id>"]}
            else:
                return "\033[31m\n[Error] No such argument available\n\033[0m"
        return str(tabulate(help_dict, headers="keys", tablefmt="fancy_grid"))

    def cli_main_loop(self):
        while True:
            try:
                command = input('\033[92m'+"[LightC2]>"+ '\033[0m')
            except KeyboardInterrupt:
                print('\033[91m'+"\n[CTRL+C] Exiting !"+ '\033[0m')
                break
            if not self.is_api_alive():
                print('\033[91m'+"[Error] Disconnected from teamserver"+ '\033[0m')
                break
            if not self.check_auth():
                self.authenticate()
            if command == "exit":
                print('\033[91m'+"\n[Exit] Exiting the cli !"+ '\033[0m')
                if input('\033[91m'+"\nAre you sure you want to exit ? (y/n) :"+ '\033[0m').lower()=="y":
                    break
            elif command == "help":
                print(self.help(None))
            elif "help" in command and len(command.split(" "))>1 and command.split(" ")[0] == "help" and command.split(" ")[1]!="":
                argument = command.split(" ")[1]
                print(self.help(argument))
            elif command == "operators":
                print(self.get_all_operators())
            elif "listener" in command and (len(command.split(" "))>=1 and command.split(" ")[0] == "listener"):
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
                        print(gen_wizard("Listener"))
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
                    else:
                        print("\033[31m\n[Error] No such argument available\n\033[0m")

            elif "vault" in command and (len(command.split(" "))>=1 and command.split(" ")[0] == "vault"):
                if command == "vault":
                    print(self.get_all_vaults())
                elif len(command.split(" "))>1 and command.split(" ")[1]!="":
                    if command.split(" ")[1]=="get" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_vault = command.split(" ")[2]
                        vault_content = self.get_vault_by_id(id_vault)
                        if vault_content:
                            print(vault_content)
                        else:
                            print("\033[31m\n[Error] Vault broken, cant decrypt it, the password/vault id may be wrong\n\033[0m")
                    elif len(command.split(" "))>1 and command.split(" ")[1]=="create":
                        vault_created = self.create_vault()
                        if vault_created:
                            print('\n\033[92m'+"[Success] Vault created\n\033[0m")
                        else:
                            print("\033[31m\n[Error] Failed to create the vault, check the logs\n\033[0m")
                    elif len(command.split(" "))>4 and command.split(" ")[1]=="add" and command.split(" ")[2]!="" and command.split(" ")[3]!="":
                        vault_id = command.split(" ")[2]
                        username_to_add = command.split(" ")[3]
                        password_to_add = command.split(" ")[4]
                        output = self.add_entry_to_vault(vault_id,username_to_add,password_to_add)
                        if not "[Error]" in output.content.decode():
                            print('\n\033[92m'+"[Success] Creds added to db\n\033[0m")
                        else:
                            print("\033[31m\n[Error] Failed to add creds, check the logs\n\033[0m")

                    elif len(command.split(" "))>3 and command.split(" ")[1]=="rm" and command.split(" ")[2]!="" and command.split(" ")[3]!="":
                        vault_id = command.split(" ")[2]
                        cred_id = command.split(" ")[3]
                        print(self.remove_entry_from_vault(vault_id,cred_id))
                    
                    elif command.split(" ")[1]=="delete" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_vault = command.split(" ")[2]
                        vault_content = self.delete_vault_by_id(id_vault)
                        if vault_content:
                            print('\n\033[92m'+"[Success] Vault deleted\n\033[0m")
                        else:
                            print("\033[31m\n[Error] Failed to delete vault, check the logs\n\033[0m")

            elif "agents" in command and (len(command.split(" "))>=1 and command.split(" ")[0] == "agents"):
                if command == "agents":
                    all_agents = self.craft_and_send_get_request("/agents").content
                    if "[Error]" in all_agents.decode():
                        print("\033[31m\n[Error] An error occured, please retry\n\033[0m")
                    else:
                        all_agents = json.loads(all_agents)
                        ordered_agents = {"\033[31mname\033[0m":[],"\033[31mlistener\033[0m":[],"\033[31muser\033[0m":[],"\033[31msleep\033[0m":[],"\033[31mpid\033[0m":[],"\033[31mlast_seen\033[0m":[],"\033[31mid\033[0m":[]}
                        for listener in all_agents["result"].keys():
                            for agent in all_agents["result"][listener].values():
                                date_from_agent = datetime.datetime.strptime(agent["last_seen"], "%Y-%m-%d %H:%M:%S")
                                now = datetime.datetime.now()
                                delta = now - date_from_agent
                                if delta.total_seconds() > 120:
                                    agent["last_seen"] = "\033[31m"+str(agent["last_seen"])+"\033[0m"
                                else:
                                    agent["last_seen"] = "\033[92m"+str(agent["last_seen"])+"\033[0m"
                                ordered_agents["\033[31mid\033[0m"].append(agent["id"])
                                ordered_agents["\033[31mname\033[0m"].append("\33[34m"+agent["name"]+"\033[0m")
                                ordered_agents["\033[31mlast_seen\033[0m"].append(agent["last_seen"])
                                ordered_agents["\033[31muser\033[0m"].append(agent["user"])
                                ordered_agents["\033[31msleep\033[0m"].append(agent["sleep"])
                                ordered_agents["\033[31mpid\033[0m"].append(agent["pid"])
                                ordered_agents["\033[31mlistener\033[0m"].append(listener)
                        print(str(tabulate(ordered_agents, headers="keys", tablefmt="fancy_grid")))
                elif len(command.split(" "))>1 and command.split(" ")[1]!="":
                    if command.split(" ")[1]=="interact" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        id_agent = command.split(" ")[2]
                        print(self.interact_with_agent(id_agent))
            
            elif "jobs" in command and (len(command.split(" "))>=1 and command.split(" ")[0] == "jobs"):
                if command == "jobs":
                    all_jobs = self.get_all_jobs("all")
                    print(str(tabulate(all_jobs, headers="keys", tablefmt="fancy_grid")))
                elif len(command.split(" "))>1 and command.split(" ")[1]!="":
                    if command.split(" ")[1]=="all":
                        all_jobs = self.get_all_jobs("all")
                        print(str(tabulate(all_jobs, headers="keys", tablefmt="fancy_grid")))
                    elif command.split(" ")[1]=="running":
                        all_jobs = self.get_all_jobs("running")
                        print(str(tabulate(all_jobs, headers="keys", tablefmt="fancy_grid")))
                    elif command.split(" ")[1]=="tasked":
                        all_jobs = self.get_all_jobs("tasked")
                        print(str(tabulate(all_jobs, headers="keys", tablefmt="fancy_grid")))
                    if command.split(" ")[1]=="get" and len(command.split(" "))>2 and command.split(" ")[2]!="":
                        job_id = command.split(" ")[2]
                        one_job = self.get_job_by_id(job_id)
                        print(one_job)





                        
                            
            else:
                print("\033[31m\n[Error] Argument not recognized\n\033[0m")

    def get_all_jobs(self,type):
        if type=="running":
            all_jobs = self.craft_and_send_get_request("/jobs").content
        elif type=="all":
            all_jobs = self.craft_and_send_get_request("/jobs/all").content
        elif type=="tasked":
            all_jobs = self.craft_and_send_get_request("/jobs/tasked").content
            
        if "[Error]" in all_jobs.decode():
            return "[Error] Error while fetching data"
        all_jobs = json.loads(all_jobs)
        ordered_jobs = {"\033[31mjob_id\033[0m":[],"\033[31magent_name\033[0m":[],"\033[31mmodule\033[0m":[],"\033[31margument\033[0m":[],"\033[31mdate_started\033[0m":[],"\033[31mstatus\033[0m":[]}
        for job_id in all_jobs.keys():
            job = all_jobs[job_id]

            
            date_from_job = datetime.datetime.strptime(job["date_started"], "%Y-%m-%d %H:%M:%S")
            now = datetime.datetime.now()
            delta = now - date_from_job
            if delta.total_seconds() > 360:
                ordered_jobs["\033[31mdate_started\033[0m"].append("\033[31m"+str(job["date_started"])+"\033[0m")
            else:
                ordered_jobs["\033[31mdate_started\033[0m"].append("\033[92m"+str(job["date_started"])+"\033[0m")

            ordered_jobs["\033[31mjob_id\033[0m"].append("\33[34m"+str(job_id)+"\033[0m")
            ordered_jobs["\033[31magent_name\033[0m"].append(job["agent"]+f" ({job['agent_id']})")
            ordered_jobs["\033[31mmodule\033[0m"].append(job["module"])
            ordered_jobs["\033[31margument\033[0m"].append(base64.b64decode(job["argument"]))

            if job["status"]=="running":
                ordered_jobs["\033[31mstatus\033[0m"].append('\033[93m'+job["status"]+"\033[0m")
            elif job["status"]=="finished":
                ordered_jobs["\033[31mstatus\033[0m"].append('\033[92m'+job["status"]+"\033[0m")
            else:
                ordered_jobs["\033[31mstatus\033[0m"].append("\033[31m"+job["status"]+"\033[0m")

        return ordered_jobs
    
    def get_job_by_id(self,job_id):
        all_jobs = self.craft_and_send_post_request("/jobs/id",{"job_id":job_id}).content
        if "[Error]" in all_jobs.decode():
            return "\033[31m\n[Error] An error occured, the id may be invalid !\n\033[0m"
        else:
            all_jobs = json.loads(all_jobs)
        all_jobs_colors = {}
        for key in all_jobs.keys():
            if key=="output" or key=="argument":
                if key=="output":
                    value = "\33[35m"+"\n"+base64.b64decode(all_jobs[key]).decode()+"\033[0m"
                else:
                    value = base64.b64decode(all_jobs[key]).decode()
                all_jobs_colors["\033[34m"+key+"\033[0m"] = value
            else:
                all_jobs_colors["\033[34m"+key+"\033[0m"] = all_jobs[key]
        output = ""
        for key in all_jobs_colors:
            output += f"{str(key)}: {all_jobs_colors[key]}\n"

        return "\n"+str(tabulate({f"\033[31mJob {str(job_id)}\033[0m":[output]}, headers="keys", tablefmt="fancy_grid"))+"\n"


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

    def interact_with_agent(self,agent_id:str):
        all_agents = self.craft_and_send_get_request("/agents").content
        all_agents = json.loads(all_agents)
        listener_to_keep = None
        agent_to_keep = None
        for listener in all_agents["result"].keys():
            for agent in all_agents["result"][listener].keys():
                if agent_id == agent:
                    agent_to_keep = all_agents["result"][listener][agent]
                    listener_to_keep = listener
        if not (listener_to_keep and agent_to_keep):
            return "\n\033[31m[Error] Check your agent id\033[0m\n"
        print('\n\033[92m'+"[Success] Getting semi-interactive shell\n\033[0m")
        print(gen_shell())
        while True:
            try:
                command = input(f"\033[31m[{agent_to_keep['name']}] #> \033[0m")
            except KeyboardInterrupt:
                print('\033[91m'+"\n\n[CTRL+C] Exiting !"+ '\033[0m')
                break
            if not self.is_api_alive():
                print('\033[91m'+"[Error] Disconnected from teamserver"+ '\033[0m')
                break
            if not self.check_auth():
                self.authenticate()
            if command=="exit":
                print("")
                break
            if len(command.split(" "))>=2 and command.split()[0]=="psh":
                print(self.exec_agent(agent_to_keep["id"],"psh"," ".join(command.split()[1:])))
            elif len(command.split(" "))>=2 and command.split()[0]=="psm":
                print(self.exec_agent(agent_to_keep["id"],"psm"," ".join(command.split()[1:])))
        return '\033[91m'+"[-] Quitting shell\n"+ '\033[0m'
            

    def exec_agent(self,agent_id,method,arguments):
        output = self.craft_and_send_post_request("/agents/exec",{"agent_id":agent_id,"method":method,"arguments":arguments})
        if not "[Error]" in output.content.decode():
            return '\n\033[92m'+"[Success] Tasked agent to run command\n\033[0m"
        else:
            return '\n\033[91m'+"[Error] Did not tasked the agent, an error occured"+ '\n\033[0m'

    def get_all_listeners(self)->str:
        listeners = self.craft_and_send_get_request("/listeners")
        if not "[Error]" in listeners.content.decode():
            all_listeners = listeners.json()['result']
            all_listeners_ordered = {'\033[31mid\033[0m':[],"\033[31mhost\033[0m":[],"\033[31mport\033[0m":[],"\033[31mssl\033[0m":[],"\033[31mactive\033[0m":[],"\033[31msecret_key\033[0m":[]}
            for listener in all_listeners:
                all_listeners_ordered["\033[31mid\033[0m"].append('\33[34m'+str(listener["host"])+":"+str(listener["port"])+"\033[0m")
                all_listeners_ordered["\033[31mhost\033[0m"].append(listener["host"])
                all_listeners_ordered["\033[31mport\033[0m"].append(listener["port"])
                all_listeners_ordered["\033[31mssl\033[0m"].append(listener["ssl"])
                all_listeners_ordered["\033[31mactive\033[0m"].append(listener["active"])
                all_listeners_ordered["\033[31msecret_key\033[0m"].append(listener["secret_key"])
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
    
    def get_vault_by_id(self,id_vault:str):
        vault_content = self.craft_and_send_post_request("/vault/id",{"password":self.password,"id":id_vault}).content.decode()
        try:
            all_entry = json.loads(vault_content)["vault_content"]
            vault_ordered = {"\033[31mindex\033[0m":[],"\033[31musername\033[0m":[],"\033[31mpassword\033[0m":[]}
            for index,entry in enumerate(all_entry):
                vault_ordered["\033[31musername\033[0m"].append(entry[0])
                vault_ordered["\033[31mpassword\033[0m"].append(entry[1])
                vault_ordered["\033[31mindex\033[0m"].append('\33[34m'+str(index)+"\033[0m")
            return str(tabulate(vault_ordered, headers="keys", tablefmt="fancy_grid"))
        except json.decoder.JSONDecodeError:
            return False
        
    def delete_vault_by_id(self,vault_id:str):
        output = self.craft_and_send_post_request("/vault/delete",{"id":vault_id})
        if "[Error]" in output.content.decode():
            return False
        else:
            return True
    
    def create_vault(self):
        output = self.craft_and_send_post_request("/vault/create",{"password":self.password})
        return "[Error]" not in output.content.decode()
    
    def add_entry_to_vault(self,vault_id:str,username_add:str,password_add:str):
        output = self.craft_and_send_post_request("/vault/add",{"id":vault_id,"password":self.password,"username_add":username_add,"password_add":password_add})
        return output
    
    def remove_entry_from_vault(self,vault_id:str,cred_index:int):
        output = self.craft_and_send_post_request("/vault/remove",{"id":vault_id,"cred_index":cred_index,"password":self.password})
        if not "[Error]" in output.content.decode():
            return '\n\033[92m'+"[Success] Entry removed from vault\033[0m\n"
        else:
            return "\n\033[31m[Error] Entry not removed from db, Check the logs\033[0m\n"
    
    def get_all_vaults(self):
        output = self.craft_and_send_get_request("/vault").json()["result"]
        ordered_vaults = {"\033[31mindex\033[0m":[],"\033[31mid\033[0m":[]}
        for index,vault_id in enumerate(output):
            ordered_vaults["\033[31mindex\033[0m"].append('\33[34m'+str(index)+"\033[0m")
            ordered_vaults["\033[31mid\033[0m"].append(vault_id)
        return str(tabulate(ordered_vaults, headers="keys", tablefmt="fancy_grid"))

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
    