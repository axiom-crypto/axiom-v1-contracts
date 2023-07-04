#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

forge create --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --constructor-args-path script/local/timelock_constructor_args --force contracts/AxiomTimelock.sol:AxiomTimelock 
