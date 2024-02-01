<div align="center">
  <img width="500px" src="assets/lightc2.jpg" />

  <p><i>Lightweight Adversary simulation command and control platform created by <a href="https://twitter.com/PPh3nX">@PPh3nX</a></i></p>
</div>

---------------------------------------------------------------------------------------------------------------------------------

## Overview

LightC2 is an modulable lightweight Adversary simulation command and control platform. It includes modules execution, cli interface, web api, custom agents/shellcodes, custom methods ...

This platform is destinated to cybersecurity experts for pentest/red team operations purposes.

![image](https://github.com/Ph3nX-Z/LightC2/assets/66122220/7dbbd941-0ce7-4726-b37d-1beab035f4a6)



## Installation

```
sudo apt install python3 python3-pip
git clone https://github.com/Ph3nX-Z/LightC2.git
cd LightC2
python3 -m pip install argon2-cffi Flask
``

## Usage

Global usage:

```py
usage: LightC2 [-h] [--password PASSWORD] [--user USER] [--register] [--register-key REGISTER_KEY] [--teamserver TEAMSERVER] mode

Minimalist C2 for short offensive missions

positional arguments:
  mode                  Specify if the script is in server mode (teamserver), or in client mode

options:
  -h, --help            show this help message and exit
  --password PASSWORD, -p PASSWORD
                        Specify a password for client mode
  --user USER, -u USER  Specify a user for client mode
  --register, -r        If set, will register the user you passed in argument (need the register key)
  --register-key REGISTER_KEY, -k REGISTER_KEY
                        Specify the key to register to team server in client mode
  --teamserver TEAMSERVER, -t TEAMSERVER
                        Specify the host (https://host:port) to connect to the team server in client mode
```
Server side example:

```sh
python3 main.py server
```

Client side example:

```sh
python3 main.py client -u "user" -p "password" --teamserver "https://127.0.0.1:8080"
```

## Features

|Feature|Category|Status|
|---|---|---|
| Argon2  | Password hashing  | Implemented  |
|  XChaCha20 | Vault Storage  |  Implemented |
| Sqlite3  | Global Storage  |  Implemented |
| Multiprocess  | Global Api  |  Implemented |
| HTTP/S  | Listener  |  Implemented |
| Tasking in db  | Jobs  |  Implemented |
| C Agent | Agent  |  In progress|
