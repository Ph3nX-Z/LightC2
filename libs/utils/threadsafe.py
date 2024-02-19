import readchar
from threading import Thread
import threading
import time

class ThreadSafe:

    def __init__(self,prompt:str="",command:str=""):
        self.command = command
        self.lock = threading.Lock()
        self.prompt = prompt
        self.stop_thread = False
        self.stop_interact = False
        self.command_buffer = []
        self.index = -1


    def thread_inputsafe(self,func):
        thread1 = Thread(target=func,args=[self.lock,self])
        thread1.start()
        return 
    
    def thread_inputsafe_arg(self,func,arg):
        thread1 = Thread(target=func,args=[self.lock,self,arg])
        thread1.start()
        return 
        
    def altprint(self,data):
        print("\n"+f"{data}"+f"\n{self.prompt}{self.command}",end="",flush=True)

    def safeinput(self,prompt):
        self.prompt = prompt

        while True:
            with self.lock:
                print(f"{self.prompt}",end="",flush=True)
            self.command = ""
            while True:
                try:
                    char = readchar.readkey()
                    try:
                        if char=="\n":
                            #print("\n"+self.command,flush=True)
                            command_output,self.command = self.command,""
                            print(flush=True)
                            self.command_buffer.append(command_output)
                            while len(self.command_buffer)>10:
                                self.command_buffer.pop(0)
                            self.index = 0
                            return command_output

                        elif char==readchar.key.BACKSPACE:
                            self.command = self.command[:-1]
                            with self.lock:
                                print("\r",end='\x1b[2K')
                                print(f"{self.prompt}{self.command}",end="",flush=True)
                        elif char==readchar.key.CTRL_C:
                            self.index = 0
                            pass

                        elif char==readchar.key.UP:
                            if abs(self.index)!=len(self.command)-1 and len(self.command_buffer)>0:
                                self.index -= 1
                                self.command = self.command_buffer[self.index]
                                with self.lock:
                                    print("\r",end='\x1b[2K')
                                    print(f"{self.prompt}{self.command}",end="",flush=True)

                        elif char==readchar.key.DOWN:
                            if self.index!=-1 and len(self.command_buffer)>0:
                                self.index += 1
                                self.command = self.command_buffer[self.index]
                                with self.lock:
                                    print("\r",end='\x1b[2K')
                                    print(f"{self.prompt}{self.command}",end="",flush=True)
                        
                        
                        elif char in [readchar.key.RIGHT,readchar.key.LEFT]:
                            pass
                            
                        else:
                            self.command+=char
                            with self.lock:
                                print(char,end="",flush=True)
                    except UnboundLocalError:
                        self.command = ""
                        print("\r",end='\x1b[2K')
                        print(f"{self.prompt}{self.command}",end="",flush=True)
                except KeyboardInterrupt:
                    self.command = ""
                    print("\r",end='\x1b[2K')
                    print(f"{self.prompt}{self.command}",end="",flush=True)
                