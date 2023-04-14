LOCAL_RPC_URL="http://localhost:8545"

# Make sure environmental variables are already exported

forge script script/AxiomDeployLocal.s.sol:AxiomDeployLocal --rpc-url $LOCAL_RPC_URL --broadcast --verify -vvvv
