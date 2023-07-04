#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env

forge create --ledger --rpc-url $MAINNET_RPC_URL --constructor-args-path script/mainnet/timelock_constructor_args --verify --etherscan-api-key $ETHERSCAN_API_KEY --force contracts/AxiomTimelock.sol:AxiomTimelock
