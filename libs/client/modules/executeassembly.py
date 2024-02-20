class ExecuteAssembly:

    def __init__(self,teamserver_obj,entire_command,agent):
        self.ts = teamserver_obj
        self.entire_command = entire_command
        self.agent = agent
    
    def run(self):
        self.ts.upload_file(self.entire_command[1])
        filename = self.entire_command[1].split("/")[-1]
        self.entire_command = filename + " " + " ".join(self.entire_command[2:])
        self.ts.exec_agent(self.agent["id"],"execute-assembly",self.entire_command)
