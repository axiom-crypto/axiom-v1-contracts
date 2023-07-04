#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

forge script script/local/AxiomV1QueryDeployLocal.s.sol:AxiomV1QueryDeployLocal --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv

#cast send --private-key $ANVIL_PRIVATE_KEY $SENDER_ADDRESS --value 100ether
#forge script script/local/AxiomV1QueryDeployLocal.s.sol:AxiomV1QueryDeployLocal --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --password $KEY_PASSWD --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv