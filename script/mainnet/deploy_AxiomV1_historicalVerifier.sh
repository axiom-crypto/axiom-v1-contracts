#!/bin/bash
cd $(git rev-parse --show-toplevel)
source .env

BYTE_CODE=`cat snark-verifiers/mainnet_17_7.v1.bin`

if [[ $(solc --yul --bin snark-verifiers/mainnet_17_7.v1.yul | tail -1) != $BYTE_CODE ]]; then
  echo "Yul bytecode does not match"
  exit 1
fi

cast send --ledger --rpc-url $MAINNET_RPC_URL --create $BYTE_CODE