#!/bin/bash
cd $(git rev-parse --show-toplevel)
source .env

# forge create --ledger --rpc-url $GOERLI_RPC_URL --constructor-args-path script/goerli/timelock_constructor_args --verify --etherscan-api-key $ETHERSCAN_API_KEY contracts/AxiomTimelock.sol:AxiomTimelock
forge create --keystore $KEYSTORE_PATH --rpc-url $GOERLI_RPC_URL --constructor-args-path script/goerli/timelock_constructor_args --verify --etherscan-api-key $ETHERSCAN_API_KEY --force contracts/AxiomTimelock.sol:AxiomTimelock
# if verify doesn't work, likely due to Cloudfare captcha, manually run on local machine:
# forge clean
# forge build
# forge verify-contract --chain 5 --watch --constructor-args-path script/goerli/timelock_constructor_args <address> contracts/AxiomTimelock.sol:AxiomTimelock
# if that also doesn't work, run:
# forge verify-contract --chain 5 --flatten --watch --compiler-version "v0.8.19+commit.7dd6d404" --constructor-args-path script/goerli/timelock_constructor_args <address> contracts/AxiomTimelock.sol:AxiomTimelock
