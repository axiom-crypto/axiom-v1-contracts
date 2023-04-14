// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import {AxiomV1Access} from "./AxiomV1Access.sol";
import {IAxiomV1Verifier} from "./interfaces/core/IAxiomV1Verifier.sol";
import {IAxiomV1StoragePf} from "./interfaces/IAxiomV1StoragePf.sol";

uint8 constant SLOT_NUMBER = 10;

/// @title  Axiom V1 Storage Proofs
/// @notice Axiom smart contract that verifies the validity of 10 storage slots of a single account in a single block using a SNARK.
/// @dev    Is a UUPS upgradeable contract.
contract AxiomV1StoragePf is IAxiomV1StoragePf, AxiomV1Access, UUPSUpgradeable {
    address public axiomAddress; // address of deployed AxiomV0 contract
    address public verifierAddress; // address of deployed ZKP verifier for storage proofs

    // slotAttestations[keccak256(blockNumber || addr || slot || slotValue)] = true
    // if and only if it has been checked that:
    //    at block number `blockNumber`, the account storage of `addr` has value `slotValue` at slot `slot`
    mapping(bytes32 => bool) public slotAttestations;

    event UpdateAxiomAddress(address newAddress);
    event UpdateSnarkVerifierAddress(address newAddress);

    /// @custom:oz-upgrades-unsafe-allow constructor
    /// @notice Prevents the implementation contract from being initialized outside of the upgradeable proxy.
    constructor() {
        _disableInitializers();
    }

    function initialize(address _axiomAddress, address _verifierAddress, address timelock, address guardian)
        public
        initializer
    {
        __UUPSUpgradeable_init();
        __AxiomV1Access_init_unchained();

        require(_axiomAddress != address(0), "AxiomV1StoragePf: axiom address is zero");
        require(_verifierAddress != address(0), "AxiomV1StoragePf: verifier address is zero");
        require(timelock != address(0), "AxiomV1StoragePf: timelock address is zero");
        require(guardian != address(0), "AxiomV1StoragePf: guardian address is zero");

        axiomAddress = _axiomAddress;
        verifierAddress = _verifierAddress;
        emit UpdateAxiomAddress(_axiomAddress);
        emit UpdateSnarkVerifierAddress(_verifierAddress);

        // prover is initialized to the contract deployer
        _grantRole(PROVER_ROLE, msg.sender);
        _grantRole(DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(TIMELOCK_ROLE, timelock);
        _grantRole(GUARDIAN_ROLE, guardian);
    }

    /// @notice Updates the address of the core AxiomV1 contract used to validate blockhashes, governed by a 'timelock'.
    ///         To avoid timelock bypass by metamorphic contracts, users should verify that
    ///         the contract deployed at `_axiomAddress` does not contain any `SELFDESTRUCT`
    ///         or `DELEGATECALL` opcodes.      
    function updateAxiomAddress(address _axiomAddress) external onlyRole(TIMELOCK_ROLE) {
        axiomAddress = _axiomAddress;
        emit UpdateAxiomAddress(_axiomAddress);
    }

    /// @notice Updates the address of the storage proof SNARK verifier contract, governed by a 'timelock'.
    ///         To avoid timelock bypass by metamorphic contracts, users should verify that
    ///         the contract deployed at `_verifierAddress` does not contain any `SELFDESTRUCT`
    ///         or `DELEGATECALL` opcodes.      
    function updateSnarkVerifierAddress(address _verifierAddress) external onlyRole(TIMELOCK_ROLE) {
        verifierAddress = _verifierAddress;
        emit UpdateSnarkVerifierAddress(_verifierAddress);
    }

    // Verify a storage proof for 10 storage slots in a single account at a single block
    function attestSlots(IAxiomV1Verifier.BlockHashWitness calldata blockData, bytes calldata proof)
        external
        onlyProver
    {
        requireNotFrozen();
        if (block.number - blockData.blockNumber <= 256) {
            if (
                !IAxiomV1Verifier(axiomAddress).isRecentBlockHashValid(blockData.blockNumber, blockData.claimedBlockHash)
            ) {
                revert("Block hash was not validated in cache");
            }
        } else {
            if (!IAxiomV1Verifier(axiomAddress).isBlockHashValid(blockData)) {
                revert("Block hash was not validated in cache");
            }
        }

        // Extract instances from proof
        // The public instances are laid out in the proof calldata as follows:
        // First 4 * 3 * 32 = 384 bytes are reserved for proof verification data used with the pairing precompile
        // 384..384 + 32 * 2: blockHash (32 bytes) as two uint128 cast to uint256, because zk proof uses 254 bit field and cannot fit uint256 into a single element
        // 384 + 32 * 2..384 + 32 * 3: blockNumber as uint256
        // 384 + 32 * 3..384 + 32 * 4: address as uint256
        // Followed by SLOT_NUMBER pairs of (slot, value)s, where slot: bytes32, value: uint256 laid out as:
        // index..index + 32 * 2: `slot` (32 bytes) as two uint128 cast to uint256, same as blockHash
        // index + 32 * 2..index + 32 * 4: `value` (32 bytes) as two uint128 cast to uint256, same as blockHash
        uint256 _blockHash = (uint256(bytes32(proof[384:384 + 32])) << 128) | uint128(bytes16(proof[384 + 48:384 + 64]));
        uint256 _blockNumber = uint256(bytes32(proof[384 + 64:384 + 96]));
        address account = address(bytes20(proof[384 + 108:384 + 128]));

        // Check block hash and block number
        if (_blockHash != uint256(blockData.claimedBlockHash)) revert("Invalid block hash in instance");
        if (_blockNumber != blockData.blockNumber) revert("Invalid block number in instance");

        (bool success,) = verifierAddress.call(proof);
        if (!success) {
            revert("Proof verification failed");
        }

        for (uint16 i = 0; i < SLOT_NUMBER; i++) {
            uint256 slot = (uint256(bytes32(proof[384 + 128 + 128 * i:384 + 160 + 128 * i])) << 128)
                | uint128(bytes16(proof[384 + 176 + 128 * i:384 + 192 + 128 * i]));
            uint256 slotValue = (uint256(bytes32(proof[384 + 192 + 128 * i:384 + 224 + 128 * i])) << 128)
                | uint128(bytes16(proof[384 + 240 + 128 * i:384 + 256 + 128 * i]));
            slotAttestations[keccak256(abi.encodePacked(blockData.blockNumber, account, slot, slotValue))] = true;
            emit SlotAttestationEvent(blockData.blockNumber, account, slot, slotValue);
        }
    }

    function isSlotAttestationValid(uint32 blockNumber, address addr, uint256 slot, uint256 slotValue)
        external
        view
        returns (bool)
    {
        requireNotFrozen();
        return slotAttestations[keccak256(abi.encodePacked(blockNumber, addr, slot, slotValue))];
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlUpgradeable)
        returns (bool)
    {
        return interfaceId == type(IAxiomV1StoragePf).interfaceId || super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address) internal override onlyRole(TIMELOCK_ROLE) {}
}
