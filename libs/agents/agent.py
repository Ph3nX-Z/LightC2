from datetime import datetime
#from name_gen import *

class Agent:

    def __init__(self,name:str,id:str,sleep:int=-1,last_seen:datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),internal_ip:str="",external_ip:str="",user:str="",process:str="",pid:int=0):
        self.name = name or generate_random_name()
        self.last_seen = last_seen
        self.internal_ip = internal_ip
        self.external_ip = external_ip
        self.user = user
        self.process = process
        self.sleep = sleep
        self.pid = pid
        self.id = id
        self.command_queue = ["whoami","azert"]
        self.output_file = []
    
    def exec_command(self,command):
        self.command_queue.append(command)

    def add_output_to_file(self,output):
        self.output_file.append(output)
        if len(self.output_file)>=10:
            self.output_file.pop(0)
