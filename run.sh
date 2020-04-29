#!/bin/bash

echo "Waiting MySQL to start..."

for i in {1..30};
do
    if ! nc -z db 3306; then
        sleep 1
    else
	sleep 5
        echo "Running Django migrations"
        python3 manage.py makemigrations
        echo "Running Django migrate"
        python3 manage.py migrate
        echo "Adding fingerprints"
        python3 manage.py add_fingerprints
        echo "Adding handlers"
        python3 manage.py add_handlers
        /usr/sbin/apachectl -D FOREGROUND
        break	
    fi	
done
