# Callback Catcher
Callback Catcher is a multi-socket control tool designed to aid in pentest activities. It has a simple web application with an backend API that allows the user control what TCP and UDP sockets should be opened on the server. It records any and all data send to the exposed sockets and logs it to a database which can be easily accessed via it's backend API. It’s kind of intended to be like the love child of Burp Collaborator and Responder. Alternatively think of it like a low/medium interactive honeypot.

Its been coded on top of the Django REST framework, which offers a number of benefits , primarily being able to create your own client scripts and tools and quickly searching and filtering of data. Opening of sockets is built on top of Python's ServerSocket library. Upon spinning up a socket a user is given the option to assign a handler to the socket, which is affectively user defined code that overwrites the ```handler``` function within the SocketServer.TCPServer and SocketServer.UDPServer classes. This code tells the socket how to handle the incoming data and what to respond with. Each connection to the socket is recorded to a database.

## How is this tool going to help me? 
1. It allows you to spin up a service really fast, arguably faster that ```nc -vlp <port>```
2. Make it quick and easy to search for what/who has connected to a service
3. Easy searching and filtering of data across multiple socket interactions
4. Vulnerable services can be easily created in Python and spun up in a matter of minutes (DNS rebind attack)

# Supported services (AKA Handlers)
Catcher suports a number of services (all of which can be wrapped in SSL) and it is relativtly easy to create your own. By default a raw TCP socket that does nothing will be opened up if no handler is defined. More details what each of these handlers can do can be found on the docs.

+ http
+ ftp
+ smtp
+ pop
+ telnet
+ mysql
+ dns
+ socket forwarding

# Dependancies
You will require Python3 in order for catcher to work. Python dependancies can be installed with:
```pip3 install -r requirements.txt```
You will also probably need to install the following packages:
```apt-get install -y libssl-dev build-essential python3-dev python3-devel sqlite3```

# How to use!
To start the Django web service, its as simple as executing the run.sh file. In order to open up sockets on ports < 1024 you need to give the script root permissions.

## Standalone script

```sh
$ ./run.sh

 _____       _ _______            _    _____       _       _
/  __ \     | | | ___ \          | |  /  __ \     | |     | |
| /  \/ __ _| | | |_/ / __ _  ___| | _| /  \/ __ _| |_ ___| |__   ___ _ __
| |    / _` | | | ___ \/ _` |/ __| |/ / |    / _` | __/ __| '_ \ / _ \ '__|
| \__/\ (_| | | | |_/ / (_| | (__|   <| \__/\ (_| | || (__| | | |  __/ |
 \____/\__,_|_|_\____/ \__,_|\___|_|\_\____/\__,_|\__\___|_| |_|\___|_|


[20/Sep/2018 08:23:00] Setting up users
[20/Sep/2018 08:23:00] Loading fingerprints
[20/Sep/2018 08:23:00] Fingerprints loaded successfully
[20/Sep/2018 08:23:00] Importing handlers
[20/Sep/2018 08:23:01] smb.py: Import failed. Skipping
[20/Sep/2018 08:23:01] 10 handlers loaded successfully
[20/Sep/2018 08:23:01] Cleaning up database
[20/Sep/2018 08:23:01] Starting service on 21/tcp
[20/Sep/2018 08:23:01] Starting service on 23/tcp
[20/Sep/2018 08:23:01] Starting service on 25/tcp
[20/Sep/2018 08:23:01] Starting service on 53/udp
[20/Sep/2018 08:23:01] Starting service on 80/tcp
[20/Sep/2018 08:23:01] Starting service on 110/tcp
[20/Sep/2018 08:23:02] Starting service on 443/tcp
[20/Sep/2018 08:23:02] Starting service on 587/tcp
[20/Sep/2018 08:23:02] Starting service on 465/tcp
[20/Sep/2018 08:23:02] Starting service on 3307/tcp
[20/Sep/2018 08:23:02] Starting service on 8000/tcp
Performing system checks...

System check identified no issues (0 silenced).
September 20, 2018 - 08:23:02
Django version 2.0.7, using settings 'catcher.settings'
Starting development server at http://0.0.0.0:12443/
Quit the server with CONTROL-C.
```

## Docker
A Dockerfile has been provided with the project and this should ease deployments. Note that you will need to build with the 'network' flag to ensure all incoming connections are directed to the docker instance.

```sh
docker build --network host -t callback-catcher .
docker run -d callback-catcher
```
