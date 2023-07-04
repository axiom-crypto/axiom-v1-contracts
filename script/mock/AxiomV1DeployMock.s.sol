// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1Mock} from "../../contracts/mock/AxiomV1Mock.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";

contract AxiomV1DeployMock is Script {
    function run() external {
        vm.startBroadcast();
        address timelock = msg.sender;
        address guardian = msg.sender;

        AxiomV1Mock implementation = new AxiomV1Mock();

        bytes memory data = abi.encodeWithSignature("initialize(address,address)", timelock, guardian);
        new AxiomProxy(address(implementation), data);
        vm.stopBroadcast();
    }
}
