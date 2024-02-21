class Whoami:

    describe_module = "Execute whoami"
    usage = "whoami"

    def __init__(self,teamserver_obj,entire_command,agent):
        self.ts = teamserver_obj
        self.entire_command = entire_command
        self.agent = agent
        
    
    def run(self):
        self.ts.exec_agent(self.agent["id"],"whoami","")