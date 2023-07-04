#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/goerli/AxiomV1DeployMock.s.sol:AxiomV1DeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $GOERLI_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv