#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/goerli/AxiomTxDeployMock.s.sol:AxiomTxDeployMock --private-key $GOERLI_PRIVATE_KEY --rpc-url $GOERLI_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv
