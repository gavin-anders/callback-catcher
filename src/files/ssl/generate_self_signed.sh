#!/bin/bash
CA_CN="CallBackCatcherCA"
CERT_CN=$1

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 360 -key ca.key -subj "/CN=$CA_CN" -out ca.crt 
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=*.$CERT_CN" -out server.csr
openssl x509 -req -days 365 -CA ca.crt -CAkey ca.key -set_serial 1 -in server.csr -out server.crt
rm server.csr
