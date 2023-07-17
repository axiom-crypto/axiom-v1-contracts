// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../../contracts/AxiomTimelock.sol";
import {AxiomExperimentalTxMock} from "../../contracts/mock/AxiomExperimentalTxMock.sol";

// This version currently deploys both AxiomV1 and AxiomV1Query contracts
contract AxiomTxDeployMock is Script {
    function run() external {
        vm.startBroadcast();

        AxiomExperimentalTxMock queryImplementation = new AxiomExperimentalTxMock();
        // AxiomTimelock timelock = new AxiomTimelock(60 /* 1 minute delay */, timelockMultisig);
        address guardian = address(0x99C7E4eB11541388535a4608C14738C24f131921);
        address timelock = address(0xc2d7e38a40808BBfc1834C79b5Ba4b27bC4c462e);
        address prover = msg.sender;

        address axiomMock = address(0x8d41105949fc6C418DfF1A76Ff5Ae69128Ade55a); // AxiomProxy of **AxiomV1Mock**
        bytes memory queryInit = abi.encodeWithSignature(
            "initialize(address,uint256,uint256,uint32,address,address,address)",
            address(axiomMock),
            10 * 1000 * 1000 gwei, // 0.01 eth
            2 ether,
            7200, // queryDeadlineInterval **in blocks** [this was a typo and we put 1 day in seconds]
            timelock,
            guardian,
            prover
        );
        console.logBytes(queryInit);
        new AxiomProxy(address(queryImplementation), queryInit);
        vm.stopBroadcast();
    }
}
