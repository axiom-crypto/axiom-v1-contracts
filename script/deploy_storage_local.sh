LOCAL_RPC_URL="http://localhost:8545"

# Make sure environmental variables are already exported

forge script script/AxiomStoragePfDeployLocal.s.sol:AxiomStoragePfDeployLocal --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv
