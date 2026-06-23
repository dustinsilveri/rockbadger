#!/bin/bash

# Generate a private key
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048

# Generate a self-signed certificate
openssl req -x509 -newkey rsa:4096 -key private.key -out certificate.crt -days 365 -nodes
