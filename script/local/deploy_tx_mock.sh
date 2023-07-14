#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

cast send --private-key $ANVIL_PRIVATE_KEY $SENDER_ADDRESS --value 100ether
forge script script/local/AxiomTxDeployMock.s.sol:AxiomTxDeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --password $KEY_PASSWD --rpc-url $LOCAL_RPC_URL --broadcast -vvvv
