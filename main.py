from datetime import datetime
import requests
import re
import os
import json
from flask import Flask, request, render_template, redirect, send_from_directory, make_response, jsonify
import random
import base64
import sys
import argparse
from handlers.http_handler import *
from libs.agents.agent import *
from libs.utils.utils import *
from libs.api.api import *
from libs.headers.gen_header import *
from libs.client.cliclient import *
import time


if __name__ == '__main__':

    print(gen_header())

    parser = argparse.ArgumentParser(
                    prog='LightC2',
                    description='Minimalist C2 for short offensive missions',
                    epilog='')
    parser.add_argument('mode',help='Specify if the script is in \33[91m\33[4mserver\33[0m mode (teamserver), or in \33[91m\33[4mclient\33[0m mode')
    parser.add_argument('--password',"-p",help='Specify a password for \33[92m\33[4mclient mode\33[0m')
    parser.add_argument('--user',"-u",help='Specify a user for \33[92m\33[4mclient mode\33[0m')
    parser.add_argument('--register',"-r",action='store_true',help='If set, will register the user you passed in argument (need the \33[92m\33[4mregister key\33[0m)')
    parser.add_argument('--register-key',"-k",help='Specify the key to register to team server in \33[92m\33[4mclient mode\33[0m')
    parser.add_argument('--teamserver',"-t",help='Specify the host \33[91m\33[4m(https://host:port)\33[0m to connect to the team server in \33[92m\33[4mclient mode\33[0m')

    args = parser.parse_args()

    mode = args.mode
    if mode not in ["server","client"]:
        parser.print_help()
        sys.exit()
    if args.password:
        password = args.password
    elif mode=="client":
        parser.print_help()
        sys.exit()
    else:
        password = None
    if args.user:
        username = args.user
    elif mode=="client":
        parser.print_help()
        sys.exit()
    else:
        username = None
    if args.register:
        register = args.register
    else:
        register = False
    if args.register_key:
        register_key = args.register_key
    elif register:
        parser.print_help()
        sys.exit()
    else:
        register_key = None
    if args.teamserver:
        teamserver = args.teamserver
    elif mode=="client":
        parser.print_help()
        sys.exit()
    else:
        teamserver = None

    #print(mode, password, username, register, register_key)

    #sys.exit()
    if mode == "server":
        header = """
--------------------
Rest API - By Ph3nX                                                 


|    Log Datetime     |     Information
---------------------------------------------------------------------------------------------------"""
        print(header)
        log_info("Server mode asked, starting api","info")
        api = C2_Rest_API()
        log_info(f"Register Key {api.register_code}","info")
        api.start_api()

    elif mode == "client":
        header = """
---------------------------
LightC2 Client - By Ph3nX                                                 

"""
        print(header)
        client = CLI_Client(teamserver,username,password,register,register_key)
        client.cli_main_loop()
        #print(client.is_api_alive())
        #print(client.authenticate())
        #print(client.get_all_operators())
        #time.sleep(2)
        #print(client.stop_listener("0.0.0.0:8182"))
        #print(client.add_listener("0.0.0.0","8282",True))
        #time.sleep(2)
        #print(client.get_all_listeners())