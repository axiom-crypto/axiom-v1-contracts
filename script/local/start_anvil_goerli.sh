#!/bin/sh
cd $(git rev-parse --show-toplevel)
source .env
anvil --fork-url $GOERLI_RPC_URL --hardfork latest --chain-id 31337
