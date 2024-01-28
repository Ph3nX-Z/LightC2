import requests
import urllib3
import json

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

    def cli_main_loop(self):
        while True:
            try:
                command = input('\033[92m'+"[LightC2]>"+ '\033[0m')
            except KeyboardInterrupt:
                print('\033[91m'+"\n[CTRL+C] Exiting !"+ '\033[0m')
                break

    def is_api_alive(self):
        try:
            if self.ssl:
                return requests.get(f"{self.teamserver_url}/",verify=False).status_code==200
            else:
                return requests.get(f"{self.teamserver_url}/").status_code==200
        except requests.exceptions.ConnectionError:
            return False
    
    def authenticate(self):
        api_key = self.craft_and_send_post_request("/auth",{"username":self.username,"password":self.password})
        if not "[Error]" in api_key.content.decode() and api_key.status_code == 200:
            self.headers["X-Auth"]=api_key.content.decode()
            return True
        return False


    def get_all_listeners(self):
        listeners = self.craft_and_send_get_request("/listeners")
        if not "[Error]" in listeners.content.decode():
            return listeners.json()
        return False
    
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
    
    def add_listener(self,host,port,ssl,admin_key=None,secret_key=None):
        data={"host":host,"port":port,"ssl":['1' if ssl else '0'][0]}
        if admin_key:
            data["admin_key"]=admin_key
        if secret_key:
            data["secret_key"]=secret_key
        output = self.craft_and_send_post_request("/listeners",data)
        print(output.content)
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            return True
        return False
    
    def get_all_operators(self):
        output = self.craft_and_send_get_request("/operators")
        if not "[Error]" in output.content.decode() and output.status_code == 200:
            output_json = json.loads(output.content.decode())
            return output_json
        return False
    