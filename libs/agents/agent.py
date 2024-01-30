import datetime
from libs.utils.utils import *

class Agent:

    def __init__(self,name:str,id:str,sleep:int=-1,last_seen:datetime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),internal_ip:str="",external_ip:str="",user:str="",pid:int=0):
        self.name = name or generate_random_name()
        self.last_seen = str(last_seen)
        self.internal_ip = internal_ip
        self.external_ip = external_ip
        self.user = user
        self.sleep = sleep
        self.pid = pid
        self.id = id
        self.command_queue = []
        self.output_file = []
    

    def add_output_to_file(self,output):
        self.output_file.append(output)
        if len(self.output_file)>=10:
            self.output_file.pop(0)
