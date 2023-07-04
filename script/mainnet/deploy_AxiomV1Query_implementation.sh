#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge create --ledger --rpc-url $MAINNET_RPC_URL --verify --etherscan-api-key $ETHERSCAN_API_KEY --force contracts/AxiomV1Query.sol:AxiomV1Query