#!/bin/bash

# Set your server URL
SERVER_URL="https://donal-may-11-1.app_9f61976ce919.cages.evervault.dev/test/deployment"

# Set the output file for the logs
OUTPUT_FILE="server_request_log.txt"

while true
do
    # Get the current timestamp
    TIMESTAMP=$(date +"%Y-%m-%d %T")

    # Make a request to the server and save the response to a variable
    RESPONSE=$(curl -s --connect-timeout 2 $SERVER_URL -H "api-key: Mzc1:5z4KHIJXKwtOvKKKHzXspSU08iZHGwuPrPlF3J6XYJSrhUWbtCO3KAEQzfyF3MdMF" -k)

    # Log the timestamp and response to the output file
    echo "$TIMESTAMP - Response: $RESPONSE"

    # Wait for 1 second
    sleep 1
done
