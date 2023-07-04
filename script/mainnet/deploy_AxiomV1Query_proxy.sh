#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/mainnet/AxiomV1QueryDeployMainnet.s.sol:AxiomV1QueryDeployMainnet --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $MAINNET_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv