// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title  Axiom Upgrades Timelock
/// @author Axiom
/// @notice Timelock controller to govern AxiomV1 smart contract upgrades.
contract AxiomTimelock is TimelockController {
    /**
     * @dev Initializes the contract with the following parameters:
     *
     * - `minDelay`: initial minimum delay (in seconds) for operations
     * - `proposers`: _multisig
     * - `executors`: _multisig
     * - `admin`: address(0) so contract is self-administered
     */
    constructor(uint256 minDelay, address _multisig)
        TimelockController(minDelay, singletonArray(_multisig), singletonArray(_multisig), address(0))
    {}
}

function singletonArray(address addr) pure returns (address[] memory) {
    require(addr != address(0), "AxiomTimelock: address is zero");
    address[] memory array = new address[](1);
    array[0] = addr;
    return array;
}
