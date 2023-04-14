// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "../contracts/libraries/MerkleMountainRange.sol";

contract MerkleMountainRangeTest is Test {
    using MerkleMountainRange for MerkleMountainRange.MMR;

    bytes32[] leaves;

    function setUp() public {
        leaves = new bytes32[](2**(17-10));
        for (uint256 i = 0; i < leaves.length; i++) {
            leaves[i] = keccak256(abi.encodePacked(i));
        }
    }

    function testAppendEmpty() public {
        MerkleMountainRange.MMR memory mmr2;
        mmr2.append(leaves);

        vm.pauseGasMetering();
        MerkleMountainRange.MMR memory mmr1;
        for (uint256 i = 0; i < leaves.length; i++) {
            mmr1.appendSingle(leaves[i]);
        }

        assert(mmr1.len == mmr2.len); // "lengths do not match");
        assert(mmr1.numPeaks == mmr2.numPeaks); // "numPeaks do not match");
        for (uint256 i = 0; i < mmr1.numPeaks; i++) {
            assert(mmr1.peaks[i] == mmr2.peaks[i]);
        }
        vm.resumeGasMetering();
    }

    function testAppendNonempty() public {
        MerkleMountainRange.MMR memory mmr2;
        vm.pauseGasMetering();
        MerkleMountainRange.MMR memory mmr1;
        uint32 len = 735; // random
        mmr1.len = len;
        mmr2.len = len;
        uint256 i;
        for (i = 0; (len >> i) != 0; i++) {
            if ((len >> i) & 1 == 1) {
                mmr1.peaks[i] = keccak256(abi.encodePacked(len >> i)); // more random
                mmr2.peaks[i] = mmr1.peaks[i];
            }
        }
        mmr1.numPeaks = uint8(i);
        mmr2.numPeaks = uint8(i);

        for (i = 0; i < leaves.length; i++) {
            mmr1.appendSingle(leaves[i]);
        }
        vm.resumeGasMetering();

        mmr2.append(leaves);

        vm.pauseGasMetering();
        assert(mmr1.len == mmr2.len); // "lengths do not match");
        assert(mmr1.numPeaks == mmr2.numPeaks); // "numPeaks do not match");
        for (i = 0; i < mmr1.numPeaks; i++) {
            // emit log_uint(i);
            // emit log_named_bytes32("mmr1", mmr1.peaks[i]);
            // emit log_named_bytes32("mmr2", mmr2.peaks[i]);
            assert(mmr1.peaks[i] == mmr2.peaks[i]); // "peaks do not match");
        }
        vm.resumeGasMetering();
    }
}
