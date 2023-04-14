// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./core/IAxiomV1Verifier.sol";

interface IAxiomV1StoragePf {
    /// @notice Stores the set of Axiom verified storage slot attestations
    /// @param  hash `slotAttestations(keccak256(blockNumber || addr || slot || slotValue)) == true` if and only if it has been checked that:
    ///         at block number `blockNumber`, the account storage of `addr` has value `slotValue` at slot `slot`
    function slotAttestations(bytes32 hash) external view returns (bool);

    /// @notice Emitted when a storage slot attestation is verified:
    ///         at block number `blockNumber`, the account storage of `addr` has value `slotValue` at slot `slot`
    event SlotAttestationEvent(uint32 blockNumber, address addr, uint256 slot, uint256 slotValue);

    /// @notice Checks if a storage slot attestation has previously been verified by Axiom. Returns true if and only if it has been checked that:
    ///         at block number `blockNumber`, the account storage of `addr` has value `slotValue` at slot `slot`
    /// @param  blockNumber The block number of the storage slot attestation
    /// @param  addr The account to check the storage slot attestation for
    /// @param  slot The storage slot
    /// @param  slotValue The value at storage slot `slot`
    function isSlotAttestationValid(uint32 blockNumber, address addr, uint256 slot, uint256 slotValue)
        external
        view
        returns (bool);

    /// @notice Verify a storage proof for 10 storage slots in a single account at a single block
    function attestSlots(IAxiomV1Verifier.BlockHashWitness calldata blockData, bytes calldata proof) external;
}
