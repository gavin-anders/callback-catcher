#!/bin/bash
HOST=0.0.0.0
PORT=12443

if [[ $EUID -ne 0 ]]; then
   echo "This script should be run as root" 
   sudo python3 manage.py runserver $HOST:$PORT
else
   python3 manage.py runserver $HOST:$PORT
fi
