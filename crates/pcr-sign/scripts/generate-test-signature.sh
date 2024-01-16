#!/bin/sh

echo "*** Generating testing Private Key ***"
openssl ecparam -name secp384r1 -genkey -out testing-priv-key.pem

echo "*** Generating testing Public Key ***"
openssl ec -in testing-priv-key.pem -pubout -out testing-pub-key.pem

echo "*** Computing test signature using private key and debug PCRs ***"
openssl dgst -sha384 -sign testing-priv-key.pem v1.demo-pcrs.txt | xxd -p - | tr -d '\n' | sed 's/^/01/' > signature.txt
