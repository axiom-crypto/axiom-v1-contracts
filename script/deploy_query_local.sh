LOCAL_RPC_URL="http://localhost:8545"

# Make sure environmental variables are already exported

forge script script/AxiomV1QueryDeployLocal.s.sol:AxiomV1QueryDeployLocal --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv
