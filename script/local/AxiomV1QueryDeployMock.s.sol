// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomV1Query} from "../../contracts/AxiomV1Query.sol";

// This version currently deploys both AxiomV1 and AxiomV1Query contracts
contract AxiomV1QueryDeployMock is Script {
    function run() external {
        vm.startBroadcast();
        // AcceptAll dummyVerifier = new AcceptAll();
        address dummyVerifier = address(0xa65CAd205ddEDBc10973D0f2C8C8C90a997990A5);
        address queryVerifierAddress = address(dummyVerifier);

        AxiomV1Query queryImplementation = new AxiomV1Query();
        // AxiomTimelock timelock = new AxiomTimelock(60 /* 1 minute delay */, timelockMultisig);
        address guardian = msg.sender;
        address timelock = msg.sender;

        address axiomProxy = vm.envAddress("AXIOM_CORE_ADDRESS"); // AxiomProxy of **AxiomV1Mock**
        bytes memory queryInit = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiomProxy),
            queryVerifierAddress,
            10 * 1000 * 1000 gwei, // 0.01 eth
            2 ether,
            7200, // queryDeadlineInterval **in blocks**, 1 day = 24 * 60 * 60 / 12 blocks
            timelock,
            guardian
        );
        new AxiomProxy(address(queryImplementation), queryInit);
        vm.stopBroadcast();
    }
}
