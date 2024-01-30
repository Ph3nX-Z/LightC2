import random
from argon2 import PasswordHasher
from argon2 import exceptions
import sqlite3
import datetime
import sys

def generate_random_name()->str:

    adjectives = ["happy","crazy","sleepy","fabulous","joyfull","cloudy","fancy","gentle","gigantic","lethal","dangerous","creepy","poisoned","anxious","sad","angry","frustrated","excited","good","bad","salty","super","mad","stealthy","giant","scary"]
    words = ["vegetables","rhino","ghost","biscuit","arrow","lightning","pivot","tunnel","pudding","salad","kiwi","whale","mountain","lake","volcano","girl","man","bro","car","cat","dog","bird","dino"]

    return " ".join([random.choice(adjectives),random.choice(words)])

def hash_password(password:str,username:str)->tuple:
    ph = PasswordHasher()
    to_hash = password+username
    hashed = ph.hash(to_hash)
    return username,hashed

def verify_password(hash:str,password:str,username:str)->bool:
    try:
        return PasswordHasher().verify(hash, password+username)
    except exceptions.VerifyMismatchError:
        return False

def db_exec(command:str,db_path:str):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    res = cur.execute(command)
    con.commit()
    output = res.fetchall()
    cur.close()
    con.close()
    return output


def log_info(message:str,status:str)->None:
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_and_startstring = {"success":'\033[92m',"error":'\033[91m',"running":'\033[93m',"info":'\033[96m',"listener":'\33[35m'}
    log = status_and_startstring[status] + f"[{now}] {message}" + f" - {status}"+ '\033[0m'
    print(log)
    with open("./logs/lightc2.logs",'a') as logfile:
        logfile.write(f"[{now}] {message}" + f" - {status}\n")
    return log

def except_ctrl_c_wrapper(f,*args,**kwargs):
    try:
        f(*args,**kwargs)
    except KeyboardInterrupt:
        log_info("CTRL+C detected, exiting !","error")
        sys.exit()


if __name__ == '__main__':
    username,hashed= hash_password("p@ssw0rd","superadmin")
    print(username,hashed)
    print(verify_password(hashed,"p@ssw0rd","superadmin"))