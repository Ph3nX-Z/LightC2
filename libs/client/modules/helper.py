from tabulate import tabulate

class Helper:

    describe_module = "Get help"
    usage = "help"

    def __init__(self,module_holder):
        self.module_holder=module_holder
    
    def run(self):
        ordered_dict_out = {"\033[31mModule Name\033[0m":[],"\033[31mModule Description\033[0m":[],"\033[31mModule Usage\033[0m":[]}
        all_modules = self.module_holder.modules
        for module_key in all_modules.keys():
            module = all_modules[module_key]
            ordered_dict_out["\033[31mModule Name\033[0m"].append("\33[34m"+module_key+"\033[0m")
            ordered_dict_out["\033[31mModule Description\033[0m"].append(module.describe_module)
            ordered_dict_out["\033[31mModule Usage\033[0m"].append(module.usage)
        print(str(tabulate(ordered_dict_out, headers="keys", tablefmt="fancy_grid")))
