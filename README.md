# Callback Catcher
A Django rest server that dynamically offers a number of vulnerable services that are used to help security researchers. The tool purposfully opens up sockets and records any incoming traffic, along with it's connection details. Callback Catcher affectivly acts like a honeypot and can create a number of different "handlers" based on user defined code. Upon connection from the client the handler attempts to detect the protocol being used and logs it to stdout as a hexdump. Callback Catcher is designed to help quickly find and extract unique values from the incoming request, based on a predefined or user supplied list. 

### How is this tool going to help me? 
It allows you to spin up a service really fast, arguably faster that ```nc -vlp <port>```
Vulnerable services can be easily created in Python and spun up in a matter of minutes
Easy greping/regex of data across multiple data sets
Aids in testing for SSRF

# Supported services (AKA Handlers)
Catcher suports a number of services and it is relativtly easy to create your own. By default a raw TCP socket that does nothing will be opened up if no handler is defined.
* http
* ftp
* smtp
* pop
* dns
* socket forwarding

# Dependancies
You will require Python3 in order for catcher to work. Python dependancies can be installed with:
```pip3 install -r requirements.txt```

# How to use!
To start the Django web service, its as simple as executing the run.sh file (NOTE - root permissions are required).
```sh
$ ./run.sh

 _____       _ _______            _    _____       _       _
/  __ \     | | | ___ \          | |  /  __ \     | |     | |
| /  \/ __ _| | | |_/ / __ _  ___| | _| /  \/ __ _| |_ ___| |__   ___ _ __
| |    / _` | | | ___ \/ _` |/ __| |/ / |    / _` | __/ __| '_ \ / _ \ '__|
| \__/\ (_| | | | |_/ / (_| | (__|   <| \__/\ (_| | || (__| | | |  __/ |
 \____/\__,_|_|_\____/ \__,_|\___|_|\_\____/\__,_|\__\___|_| |_|\___|_|


[11/Sep/2018 15:45:03] Loading fingerprints
[11/Sep/2018 15:45:03] Fingerprints loaded successfully
[11/Sep/2018 15:45:03] Cleaning up database
[11/Sep/2018 15:45:04] Using custom handler: 'ftp.py'
[11/Sep/2018 15:45:04] Using custom handler: 'static_http.py'
[11/Sep/2018 15:45:04] Using custom handler: 'static_http.py'
[11/Sep/2018 15:45:04] Using custom handler: 'static_http.py'
[11/Sep/2018 15:45:04] Using custom handler: 'dns.py'
[11/Sep/2018 15:45:04] Using custom handler: 'smtp.py'
[11/Sep/2018 15:45:04] Using custom handler: 'smtp.py'
[11/Sep/2018 15:45:04] Using custom handler: 'smtp.py'
Performing system checks...

System check identified no issues (0 silenced).
September 11, 2018 - 15:45:04
Django version 2.0.7, using settings 'catcher.settings'
Starting development server at http://0.0.0.0:12443/
Quit the server with CONTROL-C.
```

# Troubleshooting
TODO
