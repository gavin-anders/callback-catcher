#!/bin/bash

while ! mysqladmin ping -h"127.0.0.1" --silent; do
    echo "[+] DB is unavailable - sleeping"
    sleep 1
done

sleep 5
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