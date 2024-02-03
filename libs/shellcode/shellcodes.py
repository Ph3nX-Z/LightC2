class Shellcode:

    def __init__(self,shellcode_source_path:str, shellcode_bin_path:str, is_module:bool,named_pipe:str|None=None): # if is_module, you must add a namedpipe path to get the output (the default namedpipe from the agent is lightpipe)
          self.shellcode_source_path = shellcode_source_path
          self.is_module = is_module
          self.named_pipe = named_pipe or "lightpipe"
          self.shellcode_bin_path = shellcode_bin_path #that is typically the output when the shellcode is generated (.bin out path)