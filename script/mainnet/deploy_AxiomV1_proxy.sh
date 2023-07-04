#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/mainnet/AxiomV1DeployMainnet.s.sol:AxiomV1DeployMainnet --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $MAINNET_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv