#!/bin/bash

echo "[+] Waiting on MySQL to start..."

for i in {1..30};
do
    if ! nc -z db 3306; then
        sleep 1
    else
	    sleep 3
        echo "[+] Running Django migrate"
        python3 manage.py migrate
        echo "[+] Adding fingerprints"
        python3 manage.py add_fingerprints
        echo "[+] Adding handlers"
        python3 manage.py add_handlers
        echo "[+] Setting up user"
        python3 manage.py setup_user --username=$CATCHER_USERNAME --password=$CATCHER_PASSWORD
        echo "[+] Starting apache"
        /usr/sbin/apachectl -D FOREGROUND
        break	
    fi	
done
