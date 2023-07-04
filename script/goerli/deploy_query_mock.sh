#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/goerli/AxiomV1QueryDeployMock.s.sol:AxiomV1QueryDeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $GOERLI_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv

# if goerli slow and fails to verify, https://github.com/foundry-rs/foundry/issues/2435 
#forge script script/goerli/AxiomV1QueryDeployMock.s.sol:AxiomV1QueryDeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $GOERLI_RPC_URL --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv