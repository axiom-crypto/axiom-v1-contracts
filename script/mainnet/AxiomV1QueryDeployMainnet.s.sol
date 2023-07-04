// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomV1} from "../../contracts/AxiomV1.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../../contracts/AxiomTimelock.sol";
import {AxiomV1Query} from "../../contracts/AxiomV1Query.sol";

contract AxiomV1QueryDeployMainnet is Script {
    function run() external {
        vm.startBroadcast();
        address guardian = address(0xF88F9B8d445eEEBD83801d8da099695C791bc166);
        address timelock = address(0x57Dbf921727818fd2e8a3e97B4958Ab69F6b6815);
        address axiomCore = address(0x33ea514cc54b641aD8b84e4A31D311f3722D1BB5);

        // AxiomV1Query snark verifier address
        address querySnarkVerifierAddress = address(0x1aae24E24bFeCEceE5337bCb8348e2C24d8809F1);
        // AxiomV1Query implementation contract address
        address queryImplementation = address(0x34a62692915A242441b2135C9c5e115d38b14E96);

        bytes memory queryInit = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            axiomCore,
            querySnarkVerifierAddress,
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
