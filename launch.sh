#!/bin/bash

echo "dexter123" | ./build/cronosd start \
    --json-rpc.address="127.0.0.1:28545" \
    --json-rpc.ws-address="127.0.0.1:28546" \
    --json-rpc.api="eth,web3,net,txpool,debug" \
    --json-rpc.enable
