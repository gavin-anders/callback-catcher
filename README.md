# Callback Catcher
Callback Catcher is a multi-socket control tool designed to aid in pentest activities. It has a simple web application with an backend API that allows the user control what TCP and UDP sockets should be opened on the server. It records any and all data send to the exposed sockets and logs it to a database which can be easily accessed via it's backend API. It’s kind of intended to be like the love child of Burp Collaborator and Responder. Alternatively think of it like a low/medium interactive honeypot.

Its been coded on top of the Django REST framework, which offers a number of benefits , primarily being able to create your own client scripts and tools and quickly searching and filtering of data. Opening of sockets is built on top of Python's ServerSocket library. Upon spinning up a socket a user is given the option to assign a handler to the socket, which is affectively user defined code that overwrites the ```handler``` function within the SocketServer.TCPServer and SocketServer.UDPServer classes. This code tells the socket how to handle the incoming data and what to respond with. Each connection to the socket is recorded to a database.

## How is this tool going to help me? 
1. It allows you to spin up a service really fast, arguably faster that ```nc -vlp <port>```
2. Make it quick and easy to search for what/who has connected to a service
3. Easy searching and filtering of data across multiple socket interactions
4. Vulnerable services can be easily created in Python and spun up in a matter of minutes (DNS rebind attack)

# Supported Features
Catcher suports a number of services (all of which can be wrapped in SSL) and it is relativtly easy to create your own. By default a raw TCP socket that does nothing will be opened up if no handler is defined. More details what each of these handlers can do can be found on the docs.

+ http
+ ftp
+ smtp
+ pop
+ telnet
+ mysql
+ dns
+ socket forwarding

# Documentation
+ [Installation](https://bitbucket.org/gavinanders/callback-catcher/wiki/Installation)
+ [Configuration](https://bitbucket.org/gavinanders/callback-catcher/wiki/Configuration)
+ [Running](https://bitbucket.org/gavinanders/callback-catcher/wiki/Running)
+ [API](https://bitbucket.org/gavinanders/callback-catcher/wiki/API)
+ [Installation](https://bitbucket.org/gavinanders/callback-catcher/wiki/Installation)
+ [Handlers](https://bitbucket.org/gavinanders/callback-catcher/wiki/Handlers)