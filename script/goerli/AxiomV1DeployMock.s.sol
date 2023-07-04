// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1Mock} from "../../contracts/mock/AxiomV1Mock.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";

contract AxiomV1DeployMock is Script {
    function run() external {
        vm.startBroadcast();
        address guardian = address(0x99C7E4eB11541388535a4608C14738C24f131921);
        address timelock = address(0xc2d7e38a40808BBfc1834C79b5Ba4b27bC4c462e);

        AxiomV1Mock implementation = new AxiomV1Mock();

        bytes memory data = abi.encodeWithSignature("initialize(address,address)", timelock, guardian);
        new AxiomProxy(address(implementation), data);
        vm.stopBroadcast();
    }
}
