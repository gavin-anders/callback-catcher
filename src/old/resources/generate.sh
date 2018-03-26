#!/bin/sh
HOSTNAME=$(cat /etc/hostname)

rm -r ssl
mkdir ssl
cd ssl

#Comment the CA out for generation of self signed cert
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=CallBackCatcher CA"

#Generate cert and key for service ports
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=UK/ST=Lanc/O=PentestLabs/CN=*.pentestlabs.co.uk"
openssl x509 -req -days 3650 -CA ca.crt -CAkey ca.key -set_serial 1 -in server.csr -out server.crt

#Generate cert and key for api
openssl genrsa -out api.key 2048
openssl req -new -key api.key -out api.csr -subj "/C=UK/ST=Lanc/O=PentestLabs/CN=gav-pc.pentestlabs.co.uk"
openssl x509 -req -days 3650 -CA ca.crt -CAkey ca.key -set_serial 1 -in api.csr > api.cert
