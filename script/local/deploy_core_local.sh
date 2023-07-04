#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

forge script script/local/AxiomV1DeployLocal.s.sol:AxiomV1DeployLocal --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --broadcast -vvvv

#cast send --private-key $ANVIL_PRIVATE_KEY $SENDER_ADDRESS --value 100ether
#forge script script/local/AxiomV1DeployLocal.s.sol:AxiomV1DeployLocal --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --password $KEY_PASSWD --rpc-url $LOCAL_RPC_URL --broadcast -vvvv

#forge script script/local/AxiomV1Deploy.s.sol:AxiomV1Deploy --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --password $KEY_PASSWD --rpc-url $LOCAL_RPC_URL --broadcast -vvvv