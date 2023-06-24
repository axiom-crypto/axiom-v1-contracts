// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {AxiomV1} from "../contracts/AxiomV1.sol";
import {AxiomV1Core} from "../contracts/AxiomV1Core.sol";
import {AxiomProxy} from "../contracts/AxiomProxy.sol";
import {AxiomTimelock} from "../contracts/AxiomTimelock.sol";
import {AxiomV1Cheat} from "./AxiomV1.t.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {YulDeployer} from "../lib/YulDeployer.sol";

contract Proxy_Test is Test {
    address internal _implementationTest;
    address private _multisig;
    AxiomProxy proxy;
    AxiomTimelock timelock;
    YulDeployer yulDeployer;

    function setUp() public {
        yulDeployer = new YulDeployer();
        // `mainnet_10_7.v0.2` is a Yul verifier for a SNARK constraining a chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        address verifierAddress = address(yulDeployer.deployContract("mainnet_10_7.v0.2"));
        // `mainnet_17_7.v0` is a Yul verifier for a SNARK constraining a historic chain of 128 * 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateHistorical`.
        address historicalVerifierAddress = address(yulDeployer.deployContract("mainnet_17_7.v0"));
        _multisig = address(888888888);
        timelock = new AxiomTimelock(24 * 7 * 60 * 60, _multisig);

        AxiomV1Cheat implementation = new AxiomV1Cheat();
        _implementationTest = address(implementation);

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            verifierAddress,
            historicalVerifierAddress,
            address(timelock),
            address(3)
        );
        proxy = new AxiomProxy(address(implementation), data);
    }

    bytes32 internal constant IMPLEMENTATION_KEY = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    bytes32 internal constant OWNER_KEY = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    function test_implementationKey_succeeds() external {
        address impl = address(bytes20(vm.load(address(proxy), IMPLEMENTATION_KEY) << 96));
        assertEq(impl, _implementationTest);
    }

    // even updating as owner should fail because upgrades must be done via timelock
    function test_upgrade_admin_fails() external {
        vm.expectRevert();
        UUPSUpgradeable(address(proxy)).upgradeTo(address(64));
    }

    // even updating as multisig should fail because upgrades must be done via timelock
    function test_upgrade_multisig_fails() external {
        vm.prank(_multisig);
        vm.expectRevert();
        UUPSUpgradeable(address(proxy)).upgradeTo(address(64));
    }

    function test_upgrade_timelock_succeeds() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 24 * 7 * 60 * 60);

        vm.warp(block.timestamp + 24 * 7 * 60 * 60);
        vm.prank(_multisig);
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)));
    }

    // try to schedule an upgrade not as the address with proposer role
    function test_schedule_timelockNotProposer_fails() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));

        vm.prank(address(77)); // any address that is not _multisig
        vm.expectRevert();
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 24 * 7 * 60 * 60);
    }

    function test_execute_timelockNotExecutor_fails() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 24 * 7 * 60 * 60);

        vm.warp(block.timestamp + 24 * 7 * 60 * 60);

        vm.prank(address(proxy)); // any address that is not _multsig
        vm.expectRevert();
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)));
    }

    function test_execute_timelockWithoutSchedule_fails() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));

        vm.prank(_multisig);
        vm.expectRevert();
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)));
    }

    // try to schedule an upgrade with a timelock delay that is too short
    function test_schedule_timelockDelayTooShort_fails() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));

        vm.prank(_multisig);
        vm.expectRevert();
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 10);
    }

    // schedule correct but try to execute upgrade too soon
    function test_upgrade_timelockExecuteTooSoon_fails() external {
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeTo(address)", address(newImpl));
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 24 * 7 * 60 * 60);

        vm.warp(block.timestamp + 100);

        vm.prank(_multisig);
        vm.expectRevert();
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)));
    }

    function test_upgradeInitialize_timelock_fails() external {
        bytes memory initializeCall = abi.encodeWithSignature(
            "initialize(address,address,address,address)", address(0), address(0), address(timelock), address(3)
        );
        AxiomV1 newImpl = new AxiomV1();
        bytes memory data = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(newImpl), initializeCall);
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)), 24 * 7 * 60 * 60);

        vm.warp(block.timestamp + 24 * 7 * 60 * 60);

        vm.prank(_multisig);
        // cannot initialize proxy again because it is already initialized
        vm.expectRevert();

        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(1234)));
    }

    // even updating as multisig should fail because upgrades must be done via timelock
    function test_upgradeSnarkVerifier_multisig_fails() external {
        // `mainnet_10_7.v1` is an updated Yul verifier for a SNARK constraining a historic chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        address newVerifier = address(yulDeployer.deployContract("mainnet_10_7.v1"));
        vm.prank(_multisig);
        vm.expectRevert();
        AxiomV1Core(address(proxy)).upgradeSnarkVerifier(newVerifier);
    }

    function test_upgradeSnarkVerifier_timelock_succeeds() external {
        // `mainnet_10_7.v1` is an updated Yul verifier for a SNARK constraining a historic chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        address newVerifier = address(yulDeployer.deployContract("mainnet_10_7.v1"));

        bytes memory data = abi.encodeWithSignature("upgradeSnarkVerifier(address)", address(newVerifier));
        bytes32 commitHash = bytes32(hex"3922fa892f4e19eabe6885ef168a0ad42ebfd8b3");
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), commitHash, 24 * 7 * 60 * 60); // use github commit hash as the salt

        vm.warp(block.timestamp + 24 * 7 * 60 * 60);

        vm.prank(_multisig);
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(commitHash));

        // test that new verifier works properly

        // cheat
        AxiomV1Cheat(address(proxy)).setHistoricalRoot(
            0x103cbff + 1,
            keccak256(
                abi.encodePacked(
                    bytes32(hex"4a346ab08145be7cf55e51a7c9eb51ba12aad0ec6b76bc32ee58f49df685bde0"),
                    bytes32(hex"00"),
                    uint32(0)
                )
            )
        );

        // testUpdateOld
        // Valid proof for block header chain with numbers in `[0x103c800, 0x103cbff]`
        string memory path = "test/data/mainnet_10_7_103c800_103cbff.v1.calldata";
        string memory bashCommand = string.concat('cast abi-encode "f(bytes)" $(cat ', string.concat(path, ")"));

        string[] memory inputs = new string[](3);
        inputs[0] = "bash";
        inputs[1] = "-c";
        inputs[2] = bashCommand;

        bytes memory proofData = abi.decode(vm.ffi(inputs), (bytes));

        AxiomV1(address(proxy)).updateOld(bytes32(hex"00"), uint32(0), proofData);
    }

    function test_upgradeHistoricalVerifier_timelock_succeeds() external {
        // `mainnet_17_7.v1` is an updated Yul verifier for a SNARK constraining a historic chain of 128 * 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateHistorical`.
        address newVerifier = address(yulDeployer.deployContract("mainnet_17_7.v1"));
        bytes memory data = abi.encodeWithSignature("upgradeHistoricalSnarkVerifier(address)", address(newVerifier));
        vm.prank(_multisig);
        timelock.schedule(address(proxy), 0, data, bytes32(0), bytes32(uint256(0)), 24 * 7 * 60 * 60);

        vm.warp(block.timestamp + 24 * 7 * 60 * 60);

        vm.prank(_multisig);
        timelock.execute(address(proxy), 0, data, bytes32(0), bytes32(uint256(0)));
    }
}
