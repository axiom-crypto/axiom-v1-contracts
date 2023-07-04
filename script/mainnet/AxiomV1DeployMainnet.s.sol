// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";
import {AxiomProxy} from "../../contracts/AxiomProxy.sol";

contract AxiomV1DeployMainnet is Script {
    function run() external {
        vm.startBroadcast();
        address guardian = address(0xF88F9B8d445eEEBD83801d8da099695C791bc166);
        address timelock = address(0x57Dbf921727818fd2e8a3e97B4958Ab69F6b6815); // AxiomTimelock contract address

        address verifierAddress = address(0xc2d7e38a40808BBfc1834C79b5Ba4b27bC4c462e);
        address historicalVerifierAddress = address(0x24623e2C87bdF420204e21a75A5B6921950872b8);
        // AxiomV1 implementation contract address:
        address implementation = address(0x3a4Bfb0Ce7b50b6c61579c6d92E85A145350846F);

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            timelock,
            guardian
        );
        new AxiomProxy(address(implementation), data);

        vm.stopBroadcast();
    }
}
