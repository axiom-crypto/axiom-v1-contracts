// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1} from "../contracts/AxiomV1.sol";
import {AxiomProxy} from "../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../contracts/AxiomTimelock.sol";
import {AxiomV1Query} from "../contracts/AxiomV1Query.sol";

contract AxiomV1QueryDeployLocal is Script {
    function deployContract(string memory fileName) public returns (address) {
        string memory bashCommand = string.concat(
            'cast abi-encode "f(bytes)" $(solc --yul snark-verifiers/', string.concat(fileName, ".yul --bin | tail -1)")
        );

        string[] memory inputs = new string[](3);
        inputs[0] = "bash";
        inputs[1] = "-c";
        inputs[2] = bashCommand;

        bytes memory bytecode = abi.decode(vm.ffi(inputs), (bytes));

        ///@notice deploy the bytecode with the create instruction
        address deployedAddress;
        assembly {
            deployedAddress := create(0, add(bytecode, 0x20), mload(bytecode))
        }

        ///@notice check that the deployment was successful
        require(deployedAddress != address(0), "Could not deploy Yul contract");

        ///@notice return the address that the contract was deployed to
        return deployedAddress;
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("ANVIL_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        address _multisig = vm.envAddress("ANVIL_MULTISIG");

        address verifierAddress = address(deployContract("mainnet_10_7.v0.1"));
        address historicalVerifierAddress = address(deployContract("mainnet_17_7.v0"));
        address queryVerifierAddress = address(deployContract("batch_query_1"));

        AxiomV1 implementation = new AxiomV1();
        AxiomV1Query queryImplementation = new AxiomV1Query();
        AxiomTimelock timelock = new AxiomTimelock(60 * 60 * 24 * 7 /* 1 week delay */, _multisig);

        bytes memory axiomInit = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(timelock),
            msg.sender
        );
        AxiomProxy axiom = new AxiomProxy(address(implementation), axiomInit);

        bytes memory queryInit = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            queryVerifierAddress,
            10 * 1000 * 1000 gwei, 
            2 ether,
            7200,
            address(timelock),
            msg.sender
        );
        new AxiomProxy(address(queryImplementation), queryInit);

        vm.stopBroadcast();
    }
}
