// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1} from "../../contracts/AxiomV1.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../../contracts/AxiomTimelock.sol";
import {AxiomV1QueryMock} from "../../contracts/mock/AxiomV1QueryMock.sol";

// This version currently deploys both AxiomV1 and AxiomV1Query contracts
contract AxiomV1QueryDeployMock is Script {
    function run() external {
        vm.startBroadcast();

        AxiomV1QueryMock queryImplementation = new AxiomV1QueryMock();
        address timelock = msg.sender;
        address guardian = msg.sender;

        address axiomMock = address(0x8d41105949fc6C418DfF1A76Ff5Ae69128Ade55a); // AxiomProxy of **AxiomV1Mock**
        bytes memory queryInit = abi.encodeWithSignature(
            "initialize(address,uint256,uint256,uint32,address,address)",
            address(axiomMock),
            10 * 1000 * 1000 gwei, // 0.01 eth
            2 ether,
            7200, // queryDeadlineInterval **in blocks**, 1 day = 24 * 60 * 60 / 12 blocks
            timelock,
            guardian
        );
        console.logBytes(queryInit);
        new AxiomProxy(address(queryImplementation), queryInit);
        vm.stopBroadcast();
    }
}
