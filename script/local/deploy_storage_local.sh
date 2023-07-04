cd $(git rev-parse --show-toplevel)
source .env
LOCAL_RPC_URL="http://localhost:8545"

forge script script/local/AxiomV1StoragePfDeployLocal.s.sol:AxiomV1StoragePfDeployLocal --private-key $ANVIL_PRIVATE_KEY --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv
