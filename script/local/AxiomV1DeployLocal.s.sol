// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1} from "../../contracts/AxiomV1.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../../contracts/AxiomTimelock.sol";

contract AxiomV1DeployLocal is Script {
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
        // address guardian = vm.envAddress("ANVIL_MULTISIG");
        address guardian = address(0xF88F9B8d445eEEBD83801d8da099695C791bc166);
        // address timelock = address(0x57Dbf921727818fd2e8a3e97B4958Ab69F6b6815); // AxiomTimelock contract address

        address verifierAddress = address(deployContract("mainnet_10_7.v1"));
        address historicalVerifierAddress = address(deployContract("mainnet_17_7.v1"));

        AxiomV1 implementation = new AxiomV1();
        AxiomTimelock timelock = new AxiomTimelock(600, address(0xaDBbfC69F616aa16cc21003645A81C19F27Fa28f));

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(timelock),
            guardian
        );
        new AxiomProxy(address(implementation), data);

        vm.stopBroadcast();
    }
}
