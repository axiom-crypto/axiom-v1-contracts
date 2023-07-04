// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1} from "../../contracts/AxiomV1.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../../contracts/AxiomTimelock.sol";
import {AxiomV1StoragePf} from "../../contracts/AxiomV1StoragePf.sol";

contract AxiomV1StoragePfDeployLocal is Script {
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
        vm.startBroadcast();
        address timelockMultisig = vm.envAddress("ANVIL_MULTISIG");
        address guardian = vm.envAddress("ANVIL_MULTISIG");

        address verifierAddress = address(deployContract("mainnet_10_7.v1"));
        address historicalVerifierAddress = address(deployContract("mainnet_17_7.v1"));
        address storageVerifierAddress = address(deployContract("v0/storage_ts.v0.2"));

        AxiomTimelock timelock = new AxiomTimelock(60 * 60 * 24 * 7 /* 1 week delay */, timelockMultisig);

        AxiomV1 implementation = new AxiomV1();
        bytes memory axiomInit = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(timelock),
            guardian
        );
        AxiomProxy axiom = new AxiomProxy(address(implementation), axiomInit);

        AxiomV1StoragePf storageImplementation = new AxiomV1StoragePf();
        bytes memory storageInit = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            address(axiom),
            storageVerifierAddress,
            address(timelock),
            guardian
        );
        new AxiomProxy(address(storageImplementation), storageInit);

        vm.stopBroadcast();
    }
}
