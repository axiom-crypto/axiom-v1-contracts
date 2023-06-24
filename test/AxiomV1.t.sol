// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "../contracts/AxiomProxy.sol";
import "../contracts/AxiomV1.sol";
import "../contracts/libraries/MerkleTree.sol";
import "../contracts/libraries/MerkleMountainRange.sol";
import "../contracts/interfaces/core/IAxiomV1Verifier.sol";
import "../lib/YulDeployer.sol";

contract AxiomV1Cheat is AxiomV1 {
    function setHistoricalRoot(uint32 startBlockNumber, bytes32 root) public {
        AxiomV1Core.historicalRoots[startBlockNumber] = root;
    }

    function setHistoricalMMRLen(uint32 len) public {
        AxiomV1Core.historicalMMR.len = len;
    }

    function setMMRRingBuffer(uint32 mmrIdx, bytes32 mmrHash) public {
        AxiomV1Core.mmrRingBuffer[mmrIdx] = mmrHash;
    }

    function setHistoricalMMR(MerkleMountainRange.MMR calldata mmr) public {
        AxiomV1Core.historicalMMR = mmr;
    }
}

contract AxiomV1Test is Test {
    AxiomV1Cheat public axiom;
    YulDeployer yulDeployer;
    address verifierAddress;
    address historicalVerifierAddress;
    uint256 mainnetForkId1;

    function setUp() public virtual {
        yulDeployer = new YulDeployer();
        // `mainnet_10_7.v1` is a Yul verifier for a SNARK constraining a chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        verifierAddress = address(yulDeployer.deployContract("mainnet_10_7.v1"));
        // `mainnet_17_7.v0` is a Yul verifier for a SNARK constraining a historic chain of 128 * 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateHistorical`.
        historicalVerifierAddress = address(yulDeployer.deployContract("mainnet_17_7.v0"));

        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(1),
            address(22)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));

        mainnetForkId1 = vm.createFork("mainnet", 16_509_500);
        vm.makePersistent(address(implementation));
        vm.makePersistent(address(axiom));
    }

    function testInit_zeroVerifier_fail() public {
        AxiomV1 implementation = new AxiomV1();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            address(0),
            historicalVerifierAddress,
            address(1),
            address(22)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementation), data);
    }

    function testInit_zeroHistoricalVerifier_fail() public {
        AxiomV1 implementation = new AxiomV1();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", verifierAddress, address(0), address(1), address(22)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementation), data);
    }

    function testInit_zeroTimelock_fail() public {
        AxiomV1 implementation = new AxiomV1();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(0),
            address(22)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementation), data);
    }

    function testInit_zeroGuardian_fail() public {
        AxiomV1 implementation = new AxiomV1();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(11),
            address(0)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementation), data);
    }

    function testUpdateOld() public {
        vm.pauseGasMetering();
        // Valid SNARK proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.resumeGasMetering();

        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testUpdateOld_blockhash_fail() public {
        vm.pauseGasMetering();
        // Valid SNARK proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateOld(bytes32(hex"00"), uint32(1), proofData);
    }

    function testUpdateOld_proof_fail() public {
        vm.pauseGasMetering();
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // The first 32 bytes of the proof represent a field element that should be at most 88 bits (11 bytes).
        // The first 21 bytes are 0s.
        // We prank the 22nd byte to 0x53
        proofData[21] = bytes1(0x53);
        // This is now an invalid proof modified from a valid proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testUpdateOld_startBlockNumber_fail() public {
        vm.pauseGasMetering();
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // The startBlockNumber is in bytes 536:540 (see getBoundaryBlockData in AxiomV1Configuration.sol)
        // The startBlockNumber should be 0x00f99000; we prank it to 0x00f99001
        proofData[539] = bytes1(0x01);
        // This is now an invalid proof with modified `startBlockNumber` from a valid proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testUpdateOld_numFinal_fail() public {
        vm.pauseGasMetering();
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // The endBlockNumber is in bytes 540:544 (see getBoundaryBlockData in AxiomV1Configuration.sol)
        // The endBlockNumber should be 0x00f993ff; we prank it to 0x00f99400
        proofData[542] = bytes1(0x94);
        proofData[543] = bytes1(0x00);
        // This is now an invalid proof with modified `numFinal` from a valid proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testUpdateOld_notProver_fail() public {
        // Valid SNARK proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        // any address not the sender
        vm.prank(address(66));
        vm.expectRevert();
        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testGuardianFreeze() public {
        vm.prank(address(33)); // any address not guardian
        vm.expectRevert(); // "Not Guardian"
        axiom.freezeAll();

        vm.prank(address(22)); // guardian
        axiom.freezeAll();

        vm.prank(address(44)); // any address not guardian
        vm.expectRevert(); // "Not Guardian"
        axiom.unfreezeAll();
    }

    function testUpdateOld_freezeUnfreeze() public {
        vm.prank(address(22));
        axiom.freezeAll();

        // Valid SNARK proof of the chain of block headers between blocks in range `[0xf99000, 0x993ff]`.
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        axiom.setHistoricalRoot(
            16356352,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        vm.expectRevert(); // "Contract is Frozen"
        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);

        vm.prank(address(22));
        axiom.unfreezeAll();

        axiom.updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function testUpdateHistorical() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        // Valid witness data for an update for blocks in range `[0x000000, 0x01ffff]`.
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // Valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        bytes memory proofData = vm.parseBytes(vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata"));
        vm.resumeGasMetering();

        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_proof_fail() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // We prank the 3064th byte to equal 0xec
        proofData[3063] = bytes1(0xec);
        // This is now an invalid proof modified from a valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_startBlockNumber_fail() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // The startBlockNumber is in bytes 536:540 (see getBoundaryBlockData in AxiomV1Configuration.sol)
        // The startBlockNumber should be 0x00000000; we prank it to 0x00000001
        proofData[539] = bytes1(0x01);
        // This is now an invalid proof with `startBlockNumber` modified from a valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_numFinal_fail() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // We first load a correct proof
        string memory correctProofStr = vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata");
        bytes memory proofData = vm.parseBytes(correctProofStr);
        // The endBlockNumber is in bytes 540:544 (see getBoundaryBlockData in AxiomV1Configuration.sol)
        // The endBlockNumber should be 0x0001ffff; we prank it to 0x0001efff
        proofData[542] = bytes1(0xef);
        // This is now an invalid proof with `numFinal` modified from a valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_blockhash_fail() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"01"),
                    uint32(0)
                )
            )
        );
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // Valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        bytes memory proofData = vm.parseBytes(vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata"));
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_noendhash_fail() public {
        vm.pauseGasMetering();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        // Valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        bytes memory proofData = vm.parseBytes(vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata"));
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testUpdateHistorical_merkleroot_fail() public {
        vm.pauseGasMetering();
        axiom.setHistoricalRoot(
            0x20000,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"45211a1571c1c9e7fdcd25525d065303adb4c7c17c2dd7db11042fcd94ca97d4"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        roots[0] = bytes32(0x0);
        // Valid SNARK proof of the chain of block headers between blocks in range `[0x000000, 0x01ffff]`.
        bytes memory proofData = vm.parseBytes(vm.readFile("test/data/mainnet_17_7_000000_01ffff.v0.calldata"));
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateHistorical(bytes32(hex"00"), uint32(0), roots, endHashProofs, proofData);
    }

    function testAppendHistoricalMMR() public {
        vm.pauseGasMetering();
        testUpdateHistorical();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        vm.resumeGasMetering();

        bytes32[] memory _roots = new bytes32[](128);
        for (uint256 i = 0; i < 128; i++) {
            _roots[i] = roots[i];
        }
        bytes32[] memory prevHashes = new bytes32[](128);
        prevHashes[0] = bytes32(0x0);
        for (uint256 i = 1; i < 128; i++) {
            prevHashes[i] = endHashProofs[i - 1][10];
        }
        axiom.appendHistoricalMMR(0, _roots, prevHashes);
    }

    function testAppendHistoricalMMR_startBlockNumber_fail() public {
        vm.pauseGasMetering();
        testUpdateHistorical();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        vm.resumeGasMetering();

        bytes32[] memory _roots = new bytes32[](128);
        for (uint256 i = 0; i < 128; i++) {
            _roots[i] = roots[i];
        }
        bytes32[] memory prevHashes = new bytes32[](128);
        prevHashes[0] = bytes32(0x0);
        for (uint256 i = 1; i < 128; i++) {
            prevHashes[i] = endHashProofs[i - 1][10];
        }
        vm.expectRevert();
        axiom.appendHistoricalMMR(1024, _roots, prevHashes);
    }

    function testAppendHistoricalMMR_length0_fail() public {
        vm.pauseGasMetering();
        testUpdateHistorical();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (, bytes32[11][127] memory endHashProofs) = abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        vm.resumeGasMetering();

        bytes32[] memory _roots = new bytes32[](0);
        bytes32[] memory prevHashes = new bytes32[](128);
        prevHashes[0] = bytes32(0x0);
        for (uint256 i = 1; i < 128; i++) {
            prevHashes[i] = endHashProofs[i - 1][10];
        }
        vm.expectRevert();
        axiom.appendHistoricalMMR(0, _roots, prevHashes);
    }

    function testAppendHistoricalMMR_update_fail() public {
        vm.pauseGasMetering();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        vm.resumeGasMetering();

        bytes32[] memory _roots = new bytes32[](128);
        for (uint256 i = 0; i < 128; i++) {
            _roots[i] = roots[i];
        }
        bytes32[] memory prevHashes = new bytes32[](128);
        prevHashes[0] = bytes32(0x0);
        for (uint256 i = 1; i < 128; i++) {
            prevHashes[i] = endHashProofs[i - 1][10];
        }
        vm.expectRevert();
        axiom.appendHistoricalMMR(0, _roots, prevHashes);
    }

    function testAppendHistoricalMMR_rootLength_fail() public {
        vm.pauseGasMetering();
        testUpdateHistorical();
        string memory data = vm.readFile("test/data/updateHistorical_0.dat");
        (bytes32[128] memory roots, bytes32[11][127] memory endHashProofs) =
            abi.decode(vm.parseBytes(data), (bytes32[128], bytes32[11][127]));
        vm.resumeGasMetering();

        bytes32[] memory _roots = new bytes32[](127);
        for (uint256 i = 0; i < 127; i++) {
            _roots[i] = roots[i];
        }
        bytes32[] memory prevHashes = new bytes32[](128);
        prevHashes[0] = bytes32(0x0);
        for (uint256 i = 1; i < 128; i++) {
            prevHashes[i] = endHashProofs[i - 1][10];
        }
        vm.expectRevert();
        axiom.appendHistoricalMMR(0, _roots, prevHashes);
    }

    function testMmrVerifyBlockHash() public {
        vm.pauseGasMetering();
        testAppendHistoricalMMR();
        vm.resumeGasMetering();

        uint32 blockNumber = 58130;
        // Valid Merkle proof for block hash of block number 58130 into MMR of the first 131072 blocks.
        string memory data = vm.readFile("test/data/mmrProof_58130_131072.dat");
        (bytes32[] memory mmr, bytes32 claimedBlockHash, bytes32[] memory merkleProof) =
            abi.decode(vm.parseBytes(data), (bytes32[], bytes32, bytes32[]));
        axiom.mmrVerifyBlockHash(mmr, 1, blockNumber, claimedBlockHash, merkleProof);
    }

    function testMmrVerifyBlockHash_buffer_fail() public {
        vm.pauseGasMetering();
        testAppendHistoricalMMR();
        vm.resumeGasMetering();

        uint32 blockNumber = 58130;
        // Valid Merkle proof for block hash of block number 58130 into MMR of the first 131072 blocks.
        string memory data = vm.readFile("test/data/mmrProof_58130_131072.dat");
        (bytes32[] memory mmr, bytes32 claimedBlockHash, bytes32[] memory merkleProof) =
            abi.decode(vm.parseBytes(data), (bytes32[], bytes32, bytes32[]));
        mmr[0] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);
        vm.expectRevert();
        axiom.mmrVerifyBlockHash(mmr, 1, blockNumber, claimedBlockHash, merkleProof);
    }

    function testMmrVerifyBlockHash_blockNumber_fail() public {
        vm.pauseGasMetering();
        testAppendHistoricalMMR();
        vm.resumeGasMetering();

        uint32 blockNumber = 58130;
        // Valid Merkle proof for block hash of block number 58130 into MMR of the first 131072 blocks.
        string memory data = vm.readFile("test/data/mmrProof_58130_131072.dat");
        (bytes32[] memory mmr, bytes32 claimedBlockHash, bytes32[] memory merkleProof) =
            abi.decode(vm.parseBytes(data), (bytes32[], bytes32, bytes32[]));
        vm.expectRevert();
        axiom.mmrVerifyBlockHash(mmr, 1, blockNumber + 1024, claimedBlockHash, merkleProof);
    }

    function testMmrVerifyBlockHash_blockNumber_fail2() public {
        vm.pauseGasMetering();
        testAppendHistoricalMMR();
        vm.resumeGasMetering();

        uint32 blockNumber = 58130;
        // Valid Merkle proof for block hash of block number 58130 into MMR of the first 131072 blocks.
        string memory data = vm.readFile("test/data/mmrProof_58130_131072.dat");
        (bytes32[] memory mmr, bytes32 claimedBlockHash, bytes32[] memory merkleProof) =
            abi.decode(vm.parseBytes(data), (bytes32[], bytes32, bytes32[]));
        vm.expectRevert();
        axiom.mmrVerifyBlockHash(mmr, 1, blockNumber + 100024, claimedBlockHash, merkleProof);
    }

    function testMmrVerifyBlockHash_merkleProofLength_fail() public {
        vm.pauseGasMetering();
        testAppendHistoricalMMR();

        uint32 blockNumber = 58130;
        // Valid Merkle proof for block hash of block number 58130 into MMR of the first 131072 blocks.
        string memory data = vm.readFile("test/data/mmrProof_58130_131072.dat");
        (bytes32[] memory mmr, bytes32 claimedBlockHash, bytes32[] memory merkleProof) =
            abi.decode(vm.parseBytes(data), (bytes32[], bytes32, bytes32[]));
        bytes32[] memory merkleProofWrong = new bytes32[](merkleProof.length + 1);
        for (uint32 i = 0; i < merkleProof.length; i++) {
            merkleProofWrong[i] = merkleProof[i];
        }
        merkleProofWrong[merkleProof.length] = bytes32(0x0);
        vm.expectRevert();
        axiom.mmrVerifyBlockHash(mmr, 1, blockNumber, claimedBlockHash, merkleProofWrong);
        vm.resumeGasMetering();
    }

    function testBlockHash() public {
        vm.roll(16356352);
        emit log_uint(uint256(blockhash(block.number - 256)));
    }

    function testEmptyHashes() public pure {
        bytes32 empty = bytes32(0x0000000000000000000000000000000000000000000000000000000000000000);
        for (uint256 i = 0; i < 10 - 1; i++) {
            empty = keccak256(abi.encodePacked(empty, empty));
            assert(MerkleTree.getEmptyHash(i + 1) == empty);
        }
    }

    function testIsRecentBlockHashValid() public {
        vm.selectFork(mainnetForkId1);
        assert(axiom.isRecentBlockHashValid(16_509_490, blockhash(16_509_490)));
    }

    function testIsRecentBlockHashValid_blockhash_fail() public {
        vm.selectFork(mainnetForkId1);
        assert(axiom.isRecentBlockHashValid(16_509_490, blockhash(16_509_489)) == false);
    }

    function testIsRecentBlockHashValid_emptyblockhash_fail() public {
        vm.selectFork(mainnetForkId1);
        vm.expectRevert();
        axiom.isRecentBlockHashValid(16_400_000, blockhash(16_400_000));
    }

    function testSupportsInterface() public view {
        assert(axiom.supportsInterface(type(IAxiomV1).interfaceId));
    }
}
