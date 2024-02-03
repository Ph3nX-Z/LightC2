import readchar
from threading import Thread
import threading
import time
import readline

class ThreadSafe:

    def __init__(self,prompt:str="",command:str=""):
        self.command = command
        self.lock = threading.Lock()
        self.prompt = prompt


    def thread_inputsafe(self,func):
        thread1 = Thread(target=func,args=[self.lock,self])
        thread1.start()
        return 
        
    
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
                            return command_output

                        elif char==readchar.key.BACKSPACE:
                            self.command = self.command[:-1]
                            with self.lock:
                                print("\r",end='\x1b[2K')
                                print(f"{self.prompt}{self.command}",end="",flush=True)
                        elif char==readchar.key.CTRL_C:
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
                

if __name__ == "__main__":

    def print_various(lock,object):
        for _ in range(10):
            time.sleep(2)
            with lock:
                print("\n"+"[Ok From Thread]"+f"\n{object.prompt}{object.command}",end="")

    threadsafe = ThreadSafe()
    threadsafe.thread_inputsafe(print_various)
    while True:
        print("\n"+threadsafe.safeinput("Input >"),flush=True)