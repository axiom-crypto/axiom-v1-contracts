#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

AXIOM_CORE_ADDRESS="0x93d4cebef374c719ade72151bbe62f96c7fdc622" forge script script/local/AxiomV1QueryDeployMock.s.sol:AxiomV1QueryDeployMock --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --broadcast -vvvv

#cast send --private-key $ANVIL_PRIVATE_KEY $SENDER_ADDRESS --value 100ether
#AXIOM_CORE_ADDRESS="0x93d4cebef374c719ade72151bbe62f96c7fdc622" forge script script/local/AxiomV1QueryDeployMock.s.sol:AxiomV1QueryDeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --password $KEY_PASSWD --rpc-url $LOCAL_RPC_URL --broadcast -vvvv
