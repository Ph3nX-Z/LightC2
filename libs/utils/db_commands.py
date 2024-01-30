# CREATE TABLE users(username VARCHAR(50),hash VARCHAR(200),token VARCHAR(500),token_datetime VARCHAR(50),nonce VARCHAR(20));
# create table listeners(host VARCHAR(15),port INTEGER, ssl INTEGER, admin_key VARCHAR(50), secret_key VARCHAR(50),active INTEGER);
# create table vault(id VARCHAR, username VARCHAR, nonce VARCHAR, data VARCHAR);

def add_user_to_db(username:str,hash:str)->str:
    command = f"INSERT INTO users SELECT '{username}','{hash}','','','' WHERE NOT EXISTS (SELECT 1 FROM users WHERE username == '{username}');"
    return command

def check_user_in_db(username:str)->str:
    command = f'SELECT hash FROM users WHERE username=="{username}";'
    return command

def get_nonce_from_token(token:str)->str:
    command = f'SELECT nonce FROM users WHERE token=="{token}";'
    return command

def get_token_from_username(username:str)->str:
    command = f'SELECT token FROM users WHERE username=="{username}";'
    return command

def get_user_from_token(token:str)->str:
    command = f'SELECT username FROM users WHERE token=="{token}";'
    return command

def get_datetime_from_token(token:str)->str:
    command = f'SELECT token_datetime FROM users WHERE token=="{token}";'
    return command

def set_token_for_user(timecreated:str,username:str,hash:str,token:str,nonce:str)->str:
    command = f"UPDATE users SET token='{token}',token_datetime='{timecreated}',nonce='{nonce}' WHERE username=='{username}';" # be carefull, no password verification here, needs to be done before.
    return command

def get_all_operators()->str:
    command = f"SELECT username FROM users;"
    return command

def get_all_listeners()->str:
    command = "SELECT * FROM listeners;"
    return command

def check_if_listener_exists(port:int)->str:
    command = f"SELECT port FROM listeners WHERE port=={str(port)}"
    return command

def add_listener_to_db(host:str,port:int,ssl:int,active:int,secret_key:str,admin_key:str)->str:
    command = f"INSERT INTO listeners VALUES ('{host}',{str(port)},{ssl},'{admin_key}','{secret_key}',{active});"
    return command

def start_listener_update_db(port:int)->str:
    command = f"UPDATE listeners SET active=1 WHERE port=={port};"
    return command

def stop_listener_update_db(port:int)->str:
    command = f"UPDATE listeners SET active=0 WHERE port=={port};"
    return command

def is_listener_started(port:int)->str:
    command = f"SELECT active FROM listeners WHERE port=={port};"
    return command

def rm_listener_from_db(port:int)->str:
    command = f"DELETE FROM listeners WHERE port=={port};"
    return command

def add_encrypted_vault_to_db(username:str,nonce:str,id:str,data:str)->str:
    command = f"INSERT INTO vault VALUES ('{id}','{username}','{nonce}','{data}');"
    return command

def get_all_vault_for_user(username:str)->str:
    command = f"SELECT id FROM vault WHERE username=='{username}';"
    return command

def get_vault_for_user_and_id(username:str,vault_id:str)->str:
    command = f"SELECT nonce,data FROM vault WHERE username=='{username}' and id=='{vault_id}';"
    return command

def change_vault_blob(vault_id:str,blob:str)->str:
    command = f"UPDATE vault SET data='{blob}' WHERE id=='{vault_id}';"
    return command

def get_username_by_vault_id(vault_id:str)->str:
    command = f"SELECT username FROM vault WHERE id=='{vault_id}';"
    return command

def del_vault_from_id(vault_id:str)->str:
    command = f"DELETE FROM vault WHERE id=='{vault_id}';"
    return command