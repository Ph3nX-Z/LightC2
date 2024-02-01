<div align="center">
  <img width="500px" src="assets/lightc2.jpg" />

  <p><i>Lightweight Adversary simulation customized command and control platform created by <a href="https://twitter.com/PPh3nX">@PPh3nX</a></i></p>
</div>

---------------------------------------------------------------------------------------------------------------------------------

## Usage

```help
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
``
