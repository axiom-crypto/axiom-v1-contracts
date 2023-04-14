// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "../contracts/AxiomProxy.sol";
import "../contracts/AxiomV1.sol";
import "../contracts/interfaces/IAxiomV1.sol";
import "../lib/YulDeployer.sol";
import {MerkleMountainRange} from "../contracts/libraries/MerkleMountainRange.sol";

import {AxiomV1Cheat} from "../test/AxiomV1.t.sol";

contract AxiomV1UpdateRecent is Test {
    using MerkleMountainRange for MerkleMountainRange.MMR;

    AxiomV1Cheat public axiom;
    YulDeployer yulDeployer;
    uint256 mainnetForkId1;
    uint256 mainnetForkId2;
    uint256 mainnetForkId3;
    uint256 mainnetForkId4;

    function setUp() public {
        yulDeployer = new YulDeployer();
        // `mainnet_10_7.v0.1` is a Yul verifier for a SNARK constraining a chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.        
        address verifierAddress = address(yulDeployer.deployContract("mainnet_10_7.v0.1"));

        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", verifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));

        mainnetForkId1 = vm.createFork("mainnet", 16356351 + 199);
        mainnetForkId2 = vm.createFork("mainnet", 16355455 + 7);
        mainnetForkId3 = vm.createFork("mainnet", 16356351 + 300);
        mainnetForkId4 = vm.createFork("mainnet", 16356351 - 10);
        vm.makePersistent(verifierAddress);
        vm.makePersistent(address(implementation));
        vm.makePersistent(address(axiom));
    }

    event MerkleMountainRangeEvent(uint32 len, uint32 index);

    function testUpdateRecent1024() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Valid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();

        axiom.updateRecent(proofData);
        (uint32 numPeaks, uint32 len, uint32 index) = axiom.historicalMMR();
        assert(numPeaks == 0);
        assert(len == 0);
        assert(index == 0);
        bytes32 peaks0 = axiom.historicalMMRPeaks(0);
        assert(peaks0 == bytes32(0x0));
    }

    function testUpdateRecent1024_mmrUpdate() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        // 15972 = 0xf99000 >> 10
        axiom.setHistoricalMMRLen(15972);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Valid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectEmit(false, false, false, true);
        emit MerkleMountainRangeEvent(15973, 1);

        axiom.updateRecent(proofData);
        (uint32 numPeaks, uint32 len, uint32 index) = axiom.historicalMMR();
        assert(numPeaks == 1);
        assert(len == 15973);
        assert(index == 1);
    }

    function testUpdateRecent128() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId2);
        require(block.number - 256 <= 0xf9907f && 0xf9907f < block.number, "try a different block number");
        // Valid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f9907f.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();

        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_proof_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Invalid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.fail.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_proof_malformed_uint256() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Invalid SNARK for blocks in `[0xf99000, 0xf993ff]` with malformed uint256
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.fail.malformed.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }    

    function testUpdateRecent1024_numFinal_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Invalid SNARK for blocks in `[0xf99000, 0xf993ff]` with `numFinal` modified
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.fail.numFinal.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_startBlockNumber_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Invalid SNARK for blocks in `[0xf99000, 0xf993ff]` with `startBlockNumber` modified
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.fail.startBlockNumber.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_notRecentEndBlock_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId3);
        // Valid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_notRecentEndBlock2_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId4);
        // Valid SNARK for blocks in `[0xf99000, 0xf993ff]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent1024_endhash_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId1);
        require(block.number - 256 <= 0xf993ff && 0xf993ff < block.number, "try a different block number");
        // Invalid SNARK for blocks in `[0xf99000, 0xf993ff]` with `endHash` modified
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f993ff.v0.1.fail.endhash.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();
        vm.expectRevert();
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent128_notProver_fail() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId2);
        require(block.number - 256 <= 0xf9907f && 0xf9907f < block.number, "try a different block number");
        // Valid SNARK for blocks in `[0xf99000, 0xf9907f]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f9907f.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();

        vm.prank(address(66)); // not sender = prover
        vm.expectRevert(); // NotProver
        axiom.updateRecent(proofData);
    }

    function testUpdateRecent128_freezeUnfreeze() public {
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId2);
        require(block.number - 256 <= 0xf9907f && 0xf9907f < block.number, "try a different block number");
        // Valid SNARK for blocks in `[0xf99000, 0xf9907f]`
        string memory proofStr = vm.readFile("test/data/mainnet_10_7_f99000_f9907f.v0.1.calldata");
        bytes memory proofData = vm.parseBytes(proofStr);
        vm.resumeGasMetering();

        vm.prank(address(3)); // Guardian
        axiom.freezeAll();

        vm.expectRevert(); // ContractIsFrozen
        axiom.updateRecent(proofData);

        vm.prank(address(3));
        axiom.unfreezeAll();

        axiom.updateRecent(proofData);
    }

    function testIsBlockHashValid() public {
        uint256 start = 0xf99000;
        uint256 end = 0xf9907f;
        testUpdateRecent128();
        require(start > block.number - 256, "start number is not recent");
        require(end < block.number, "end number in not recent");
        bytes32 prevHash = blockhash(start - 1);
        bytes32[][] memory merkleRoots = new bytes32[][](11);
        merkleRoots[0] = new bytes32[](1024);
        for (uint256 i = 0; i < 1024; i++) {
            if (i <= end - start) {
                merkleRoots[0][i] = blockhash(start + i);
            } else {
                merkleRoots[0][i] = bytes32(0);
            }
        }
        for (uint256 depth = 0; depth < 10; depth++) {
            merkleRoots[depth + 1] = new bytes32[](2 ** (10 - depth - 1));
            for (uint256 i = 0; i < 2 ** (10 - depth - 1); i++) {
                merkleRoots[depth + 1][i] =
                    keccak256(abi.encodePacked(merkleRoots[depth][2 * i], merkleRoots[depth][2 * i + 1]));
            }
        }

        bytes32[10] memory merkleProof;
        for (uint256 side = 0; side < 128; side++) {
            bytes32 blockHash = blockhash(start + side);
            for (uint32 depth = 0; depth < 10; depth++) {
                merkleProof[depth] = merkleRoots[depth][(side >> depth) ^ 1];
            }
            assert(
                axiom.isBlockHashValid(
                    IAxiomV1Verifier.BlockHashWitness(
                        uint32(start + side), blockHash, prevHash, uint32(end - start + 1), merkleProof
                    )
                )
            );
        }
    }

    function testIsBlockHashValid_notStored_fail() public {
        uint256 start = 0xf99000;
        uint256 end = 0xf9907f;
        vm.pauseGasMetering();
        vm.selectFork(mainnetForkId2);
        vm.resumeGasMetering();
        require(start > block.number - 256, "start number is not recent");
        require(end < block.number, "end number in not recent");
        bytes32 prevHash = blockhash(start - 1);
        bytes32[][] memory merkleRoots = new bytes32[][](11);
        merkleRoots[0] = new bytes32[](1024);
        for (uint256 i = 0; i < 1024; i++) {
            if (i <= end - start) {
                merkleRoots[0][i] = blockhash(start + i);
            } else {
                merkleRoots[0][i] = bytes32(0);
            }
        }
        for (uint256 depth = 0; depth < 10; depth++) {
            merkleRoots[depth + 1] = new bytes32[](2 ** (10 - depth - 1));
            for (uint256 i = 0; i < 2 ** (10 - depth - 1); i++) {
                merkleRoots[depth + 1][i] =
                    keccak256(abi.encodePacked(merkleRoots[depth][2 * i], merkleRoots[depth][2 * i + 1]));
            }
        }

        bytes32[10] memory merkleProof;
        bytes32 blockHash = blockhash(start);
        for (uint32 depth = 0; depth < 10; depth++) {
            merkleProof[depth] = merkleRoots[depth][0];
        }
        vm.expectRevert();
        axiom.isBlockHashValid(
            IAxiomV1Verifier.BlockHashWitness(uint32(start), blockHash, prevHash, uint32(end - start + 1), merkleProof)
        );
    }

    function testIsBlockHashValid_zeroBlockHash_fail() public {
        uint256 start = 0xf99000;
        uint256 end = 0xf9907f;
        testUpdateRecent128();
        require(start > block.number - 256, "start number is not recent");
        require(end < block.number, "end number in not recent");
        bytes32 prevHash = blockhash(start - 1);
        bytes32[][] memory merkleRoots = new bytes32[][](11);
        merkleRoots[0] = new bytes32[](1024);
        for (uint256 i = 0; i < 1024; i++) {
            if (i <= end - start) {
                merkleRoots[0][i] = blockhash(start + i);
            } else {
                merkleRoots[0][i] = bytes32(0);
            }
        }
        for (uint256 depth = 0; depth < 10; depth++) {
            merkleRoots[depth + 1] = new bytes32[](2 ** (10 - depth - 1));
            for (uint256 i = 0; i < 2 ** (10 - depth - 1); i++) {
                merkleRoots[depth + 1][i] =
                    keccak256(abi.encodePacked(merkleRoots[depth][2 * i], merkleRoots[depth][2 * i + 1]));
            }
        }

        bytes32[10] memory merkleProof;
        for (uint32 depth = 0; depth < 10; depth++) {
            merkleProof[depth] = merkleRoots[depth][(1 >> depth) ^ 1];
        }
        vm.expectRevert();
        axiom.isBlockHashValid(
            IAxiomV1Verifier.BlockHashWitness(uint32(start + 1), 0x0, prevHash, uint32(end - start + 1), merkleProof)
        );
    }
}
