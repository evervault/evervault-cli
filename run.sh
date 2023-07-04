#!/bin/sh
sleep 5
echo "Checking status of data-plane"
SVDIR=/etc/service sv check data-plane || exit 1
echo "Data-plane up and running"
while ! grep -q "EV_CAGE_INITIALIZED" /etc/customer-env
 do echo "Env not ready, sleeping user process for one second"
 sleep 1
done 
. /etc/customer-env

echo "Booting user service..."
cd %s\n
exec node /index.js
\n" "$PWD"