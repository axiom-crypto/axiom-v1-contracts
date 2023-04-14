// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "./AxiomV1.t.sol";
import "../contracts/interfaces/IAxiomV1Query.sol";
import "../contracts/AxiomV1Query.sol";
import "../lib/YulDeployer.sol";

uint32 constant testBlockNumber = 16329190;
uint32 constant testPrevBlockNumber = 16328704;
bytes32 constant testBlockHash = bytes32(hex"eaa53f3fbfe912c45af96f4a1a34e3cb1de8e9ac1b6fe8d8b1c9eadad976eda9");
bytes32 constant testPrevHash = bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d");
bytes32 constant testRoot = bytes32(hex"94768cc8e722c0dfa1be6e2326573764102b7a80685a3e98d340ab121e7277cd");
address constant testAddress = 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB;
uint32 constant testNumFinal = 0;

contract AxiomV1QueryTest is Test {
    AxiomV1Cheat public axiom;
    AxiomV1Query private implementationQu = new AxiomV1Query();
    AxiomV1Query public axiomQuery;
    YulDeployer yulDeployer;

    address axiomVerifierAddress;
    address mmrVerifierAddress;
    uint256 minQueryPrice;
    uint256 maxQueryPrice;
    uint32 queryDeadlineInterval;

    bytes proof;
    bytes proofTrunc;
    bytes proofFail;

    bytes proofOld;

    function setUp() public {
        yulDeployer = new YulDeployer();
        axiomVerifierAddress = address(yulDeployer.deployContract("mainnet_10_7.v0.1"));
        mmrVerifierAddress = address(yulDeployer.deployContract("batch_query_1"));
        vm.makePersistent(axiomVerifierAddress);
        vm.makePersistent(mmrVerifierAddress);
        vm.makePersistent(address(implementationQu));

        minQueryPrice = 10 * 1000 * 1000 gwei;
        maxQueryPrice = 2 ether;
        queryDeadlineInterval = 7200;

        proof = vm.parseBytes(vm.readFile("test/data/mmr_recent.calldata"));
        proofTrunc = vm.parseBytes(vm.readFile("test/data/mmr_recent_truncate.calldata"));
        proofFail = vm.parseBytes(vm.readFile("test/data/mmr_recent_fail.calldata"));

        proofOld = vm.parseBytes(vm.readFile("test/data/mmr_old.calldata"));
    }

    function deploy() public {
        // vm.pauseGasMetering(); // reverts when pauseGasMetering is used, unknown reason
        vm.roll(16428704);
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            mmrVerifierAddress,
            minQueryPrice,
            maxQueryPrice,
            queryDeadlineInterval,
            address(1),
            address(3)
        );
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
        // vm.resumeGasMetering();
    }

    function testInit_zeroVerifier() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            address(0),
            minQueryPrice,
            maxQueryPrice,            
            queryDeadlineInterval,
            address(1),
            address(3)
        );
        vm.expectRevert();
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
    }

    function testInit_zeroAddress() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(0),
            mmrVerifierAddress,
            minQueryPrice,
            maxQueryPrice,
            queryDeadlineInterval,
            address(1),
            address(3)
        );
        vm.expectRevert();
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
    }    

    function testInit_zeroTimelock() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            mmrVerifierAddress,
            minQueryPrice,
            maxQueryPrice,
            queryDeadlineInterval,
            address(0),
            address(3)
        );
        vm.expectRevert();
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
    }    

    function testInit_zeroGuardian() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            mmrVerifierAddress,
            minQueryPrice,
            maxQueryPrice,
            queryDeadlineInterval,
            address(1),
            address(0)
        );
        vm.expectRevert();
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
    }

    function testSendOffchainQuery_price_fail() public {
        deploy();
        vm.expectRevert();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendOffchainQuery(
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1), 
            payable(address(1)), 
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1)
        );
    }

    function testSendOffchainQuery_price2_fail() public {
        deploy();
        vm.expectRevert();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendOffchainQuery{value: 9999999 gwei}(
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1), 
            payable(address(1)), 
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1)
        );
    }

    function testSendOffchainQuery_price3_fail() public {
        deploy();
        vm.expectRevert();
        vm.deal(address(100), 3 ether);
        vm.prank(address(100));
        axiomQuery.sendOffchainQuery{value: 2_000_000_001 gwei}(
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1), 
            payable(address(1)), 
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1)
        );
    }    

    event QueryInitiatedOffchain(bytes32 keccakQueryResponse, uint256 payment, uint32 deadlineBlockNumber, address refundee, bytes32 ipfsHash);

    function testSendOffchainQuery() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes32 ipfsHash = bytes32(0xf4eaaa9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        vm.roll(16508329);
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        vm.expectEmit(false, false, false, true);
        emit QueryInitiatedOffchain(
            keccakQueryResponse,
            10 * 1000 * 1000 gwei,
            16508329 + queryDeadlineInterval,
            address(12),
            ipfsHash
        );
        axiomQuery.sendOffchainQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            ipfsHash
        );
        (uint256 payment, IAxiomV1Query.AxiomQueryState state, uint32 deadlineBlockNumber, address payable refundee) = axiomQuery.queries(keccakQueryResponse);        
        assert(payment == 10 * 1000 * 1000 gwei);
        assert(state == IAxiomV1Query.AxiomQueryState.Active);
        assert(deadlineBlockNumber == 16508329 + queryDeadlineInterval);
        assert(refundee == address(12));
    }

    function testSendOffchainQuery2() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes32 ipfsHash = bytes32(0xf4eaaa9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        vm.roll(16508329);
        vm.deal(address(100), 3 ether);
        vm.prank(address(100));
        vm.expectEmit(false, false, false, true);
        emit QueryInitiatedOffchain(
            keccakQueryResponse,
            2 ether,
            16508329 + queryDeadlineInterval,
            address(12),
            ipfsHash
        );
        axiomQuery.sendOffchainQuery{value: 2 ether}(
            keccakQueryResponse, 
            payable(address(12)),
            ipfsHash
        );
        (uint256 payment, IAxiomV1Query.AxiomQueryState state, uint32 deadlineBlockNumber, address payable refundee) = axiomQuery.queries(keccakQueryResponse);        
        assert(payment == 2 ether);
        assert(state == IAxiomV1Query.AxiomQueryState.Active);
        assert(deadlineBlockNumber == 16508329 + queryDeadlineInterval);
        assert(refundee == address(12));
    }    

    function testSendOffchainQuery_active_fail() public {
        testSendOffchainQuery();
        vm.expectRevert();
        axiomQuery.sendOffchainQuery{value: 10 * 1000 * 1000 gwei}(
            bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1),
            payable(address(11)), 
            bytes32(0xf4eaaa9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1)
        );
    }

    event QueryInitiatedOnchain(bytes32 keccakQueryResponse, uint256 payment, uint32 deadlineBlockNumber, address refundee, bytes32 queryHash);

    function testSendOnchainQuery() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes memory query = hex"f4aeaaa9f45a8c40aaaaaaaa0a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f32322321";
        bytes32 queryHash = keccak256(query);
        vm.roll(16508329);
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        vm.expectEmit(false, false, false, true);
        emit QueryInitiatedOnchain(
            keccakQueryResponse,
            10 * 1000 * 1000 gwei,
            16508329 + queryDeadlineInterval,
            address(12),
            queryHash
        );
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );
        (uint256 payment, IAxiomV1Query.AxiomQueryState state, uint32 deadlineBlockNumber, address payable refundee) = axiomQuery.queries(keccakQueryResponse);        
        assert(payment == 10 * 1000 * 1000 gwei);
        assert(state == IAxiomV1Query.AxiomQueryState.Active);
        assert(deadlineBlockNumber == 16508329 + queryDeadlineInterval);
        assert(refundee == address(12));
    }

    function testSendOnchainQuery_price_fail() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes memory query = hex"f4aeaaa9f45a8c40aaaaaaaa0a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f32322321";
        vm.roll(16508329);
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        vm.expectRevert();
        axiomQuery.sendQuery{value: 8 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );
    }

    function testSendOnchainQuery_price2_fail() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes memory query = hex"f4aeaaa9f45a8c40aaaaaaaa0a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f32322321";
        vm.roll(16508329);
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        vm.expectRevert();
        axiomQuery.sendQuery(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );
    }    

    function testSendOnchainQuery_price3_fail() public {
        deploy();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        bytes memory query = hex"f4aeaaa9f45a8c40aaaaaaaa0a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f32322321";
        vm.roll(16508329);
        vm.deal(address(100), 3 ether);
        vm.prank(address(100));
        vm.expectRevert();
        axiomQuery.sendQuery{value: 2_000_000_001 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );
    }  

    event QueryRefunded(bytes32 keccakQueryResponse, uint256 payment, uint32 deadlineBlockNumber, address refundee);

    function testCollectRefund() public {
        testSendOffchainQuery();
        bytes32 keccakQueryResponse = bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1);
        vm.roll(16508329 + queryDeadlineInterval + 1);
        vm.expectEmit(false, false, false, true);
        emit QueryRefunded(
            keccakQueryResponse,
            10 * 1000 * 1000 gwei,
            16508329 + queryDeadlineInterval,
            address(12)
        );        
        axiomQuery.collectRefund(keccakQueryResponse);
        (uint256 payment, IAxiomV1Query.AxiomQueryState state, uint32 deadlineBlockNumber, address payable refundee) = axiomQuery.queries(keccakQueryResponse);        
        assert(payment == 0);
        assert(state == IAxiomV1Query.AxiomQueryState.Inactive);
        assert(deadlineBlockNumber == 0);
        assert(refundee == payable(address(0)));
    } 

    function testCollectRefund_early_fail() public {
        testSendOffchainQuery();
        vm.roll(16508329 + queryDeadlineInterval);
        vm.expectRevert();
        axiomQuery.collectRefund(bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1));
    }     

    function testCollectRefund_double_fail() public {
        testCollectRefund();
        vm.expectRevert();
        axiomQuery.collectRefund(bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1));
    }

    function testCollectRefund_after_fulfill_fail() public {
        testFulfillQueryVsMMR();
        bytes32 keccakQueryResponse = keccak256(abi.encodePacked(
            bytes32(0x26c48c9d0c1cc90c5abd0fcd60baa7b131e36759454dec1e6909660c3221045a),
            bytes32(0x266493174c49d4d1ae91511c4e37c44387b5eb95a23a9b60ed4e60135932b8ac),
            bytes32(0xdd6360f456292094f58669736b3f45854133882bdc09acb006a386a743a14f8d)
        ));        
        vm.expectRevert();
        axiomQuery.collectRefund(keccakQueryResponse);        
    }

    event UpdateMinQueryPrice(uint256 minQueryPrice);

    function testUpdateMinQueryPrice() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateMinQueryPrice(10);
        axiomQuery.updateMinQueryPrice(10);
    }

    function testUpdateMinQueryPrice_fail() public {
        deploy();
        vm.prank(address(11));
        vm.expectRevert();
        axiomQuery.updateMinQueryPrice(10);
    }   

    event UpdateMaxQueryPrice(uint256 maxQueryPrice);

    function testUpdateMaxQueryPrice() public {
        deploy();
        assert(axiomQuery.maxQueryPrice() == 2 ether);
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateMaxQueryPrice(1 ether);
        axiomQuery.updateMaxQueryPrice(1 ether);
        assert(axiomQuery.maxQueryPrice() == 1 ether);
    }

    function testUpdateMaxQueryPrice_fail() public {
        deploy();
        vm.prank(address(11));
        vm.expectRevert();
        axiomQuery.updateMaxQueryPrice(2 ether);
    }         

    event UpdateQueryDeadlineInterval(uint32 queryDeadlineInterval);

    function testUpdateQueryDeadlineInterval() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateQueryDeadlineInterval(10);
        axiomQuery.updateQueryDeadlineInterval(10);
    }

    function testUpdateQueryDeadlineInterval_fail() public {
        deploy();
        vm.prank(address(11));
        vm.expectRevert();
        axiomQuery.updateQueryDeadlineInterval(10);
    }    

    event UpdateAxiomAddress(address addr);

    function testUpdateAxiomAddress() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateAxiomAddress(address(100));

        axiomQuery.updateAxiomAddress(address(100));
    }

    function testUpdateAxiomAddress_fail() public {
        deploy();
        vm.prank(address(10));
        vm.expectRevert();
        axiomQuery.updateAxiomAddress(address(100));
    }    

    event UpdateMMRVerifierAddress(address addr);

    function testUpdateMMRVerifierAddress() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateMMRVerifierAddress(address(100));

        axiomQuery.updateMMRVerifierAddress(address(100));
    }

    function testUpdateMMRVerifierAddress_fail() public {
        deploy();
        vm.prank(address(10));
        vm.expectRevert();
        axiomQuery.updateMMRVerifierAddress(address(100));
    }                             

    function testSupportsInterface() public {
        deploy();
        assert(axiomQuery.supportsInterface(type(IAxiomV1Query).interfaceId));
    }

    function deployRecent() public {
        // vm.pauseGasMetering(); // reverts when pauseGasMetering is used, unknown reason
        vm.createSelectFork("mainnet", 16_525_312 + 1000);
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,uint256,uint256,uint32,address,address)",
            address(axiom),
            mmrVerifierAddress,
            minQueryPrice,
            maxQueryPrice,
            queryDeadlineInterval,
            address(1),
            address(3)
        );
        vm.prank(address(111));
        AxiomProxy proxyQu = new AxiomProxy(address(implementationQu), data);
        axiomQuery = AxiomV1Query(payable(address(proxyQu)));
        // vm.resumeGasMetering();
    }

    function setupFulfill() public pure returns (bytes32 keccakQueryResponse, bytes memory query) {
        keccakQueryResponse = keccak256(abi.encodePacked(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530c7),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f)
        ));
        query = hex"f4aeaaa9f45a8c40aaaaaaaa0a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f32322321";
    }

    function testFulfillQueryVsMMR() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();

        (bytes32 keccakQueryResponse, bytes memory query) = setupFulfill();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );

        vm.prank(address(111));
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);

        (, IAxiomV1Query.AxiomQueryState state, ,) = axiomQuery.queries(keccakQueryResponse);        
        assert(state == IAxiomV1Query.AxiomQueryState.Fulfilled);
    }

    function testFulfillQueryVsMMR_fail_twice() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();

        (bytes32 keccakQueryResponse, bytes memory query) = setupFulfill();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );

        vm.prank(address(111));
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);

        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);
    }

    function testFulfillQueryVsMMR_fail_state_inactive() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        (bytes32 keccakQueryResponse, ) = setupFulfill();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);
    }

    function testFulfillQueryVsMMR_fail_state_refunded() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        (bytes32 keccakQueryResponse, bytes memory query) = setupFulfill();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );
        vm.roll(16_525_312 + 1000 + queryDeadlineInterval + 1);
        axiomQuery.collectRefund(keccakQueryResponse);

        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);
    }

    function testFulfillQueryVsMMR_fail_proof() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        (bytes32 keccakQueryResponse, bytes memory query) = setupFulfill();
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );

        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proofFail);
    }

    function testFulfillQueryVsMMR_fail_resp() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        (bytes32 keccakQueryResponse, bytes memory query) = setupFulfill();
        keccakQueryResponse = bytes32(0x12c48c9d0c1cc90c5abd0fcd60baa7b131e36759454dec1e6909660c3221045a);
        vm.deal(address(100), 1 ether);
        vm.prank(address(100));
        axiomQuery.sendQuery{value: 10 * 1000 * 1000 gwei}(
            keccakQueryResponse, 
            payable(address(12)),
            query
        );

        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.fulfillQueryVsMMR(keccakQueryResponse, payable(address(12)), 2, mmrWitness, proof);
    }                  

    function testIsKeccakResultValid() public {
        testFulfillQueryVsMMR();
        assert(axiomQuery.isKeccakResultValid(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530c7),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f)
        ));
    }

    function testIsKeccakResultValid_fail() public {
        deployRecent();
        bool isValid = axiomQuery.isKeccakResultValid(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530ca),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f)
        );
        assert(!isValid);
    }

    function testIsPoseidonResultValid() public {
        testFulfillQueryVsMMR();
        assert(axiomQuery.isPoseidonResultValid(
            bytes32(0x091ecc3df9cfe52bdbf1bad5c6a7f8aa4416fab9b6a61152692d30d6c510c647),
            bytes32(0x0c79375f0e6e921f718640d65d36b4c0881ef22c9b245769236145725556c5b7),
            bytes32(0x2e1b4dac392cebfa1bbf4bb424a53a798ddaa129e15cc86f46e66630d4d7cb73)
        ));
    }

    function testIsPoseidonResultValid_fail() public {
        deployRecent();
        bool isValid = axiomQuery.isPoseidonResultValid(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530ca),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f)
        );
        assert(!isValid);
    }    

    function testAreResponsesValid_null() public {
        testFulfillQueryVsMMR();
        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530c7),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f),
            new IAxiomV1Query.BlockResponse[](0),
            new IAxiomV1Query.AccountResponse[](0),
            new IAxiomV1Query.StorageResponse[](0)
        );
        assert(isValid);
    }       

    function testAreResponsesValid_fail() public {
        deployRecent();
        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530c7),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80a3d2ed449f4bb63f),
            new IAxiomV1Query.BlockResponse[](1),
            new IAxiomV1Query.AccountResponse[](1),
            new IAxiomV1Query.StorageResponse[](1)
        );
        assert(!isValid);
    }    

    function getResponses() public pure returns (
        IAxiomV1Query.BlockResponse[] memory blockResponses,
        IAxiomV1Query.AccountResponse[] memory accountResponses,
        IAxiomV1Query.StorageResponse[] memory storageResponses
    ) {
        blockResponses = new IAxiomV1Query.BlockResponse[](1);
        blockResponses[0] = IAxiomV1Query.BlockResponse({
            blockNumber:0x00e4a8de,
            blockHash:0xf907e3fbe5dcb0dfc6682ba5d0827386ca8d7431ba040b9f5169dcb9b44e664a,
            leafIdx:0,
            proof:[
                bytes32(0x85a6078963b11c9cf7e4a4d7ca3724ddbd20e5a928c075876a8c5047f37ab38f),
                bytes32(0xc1fd0abea38ee97c312e08725133ac03719ac2f5efbbd802b8f860b7b882f68c),
                bytes32(0xc51fd49a249e7392b09f77f6f248110b9e00245ca43ab50d9f9c63534bd4bdf0),
                bytes32(0x2ec8f5e73b29ce0f042a85b7ec14b9067751c24b09a814245adc790b05de88f7),
                bytes32(0x11ed23aad11d9f4b44d63697aaf6ba73a9611e3a60d4db30817fcd23f17f88bb),
                bytes32(0x1c1a4944d8efce5d2503b9cd348e8c3c72da26bd8a893321df0e1b8e1f1fb8e8)
            ]  
        });     
        accountResponses = new IAxiomV1Query.AccountResponse[](1);
        accountResponses[0] = IAxiomV1Query.AccountResponse({
            blockNumber:0x00e4a8de,
            addr:address(0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03),
            nonce:0x0000000000000001,
            balance:0x000000000000000000000000,
            storageRoot:bytes32(0x9c3a96f4bfc05ccaa0e9afede34db54dc538a472cb02745945f69946e7b83b77),
            codeHash:bytes32(0xd4e5a9dff22acb675a291c79616f91b1526ce1a84dff4bd9695f3f39ae779f11),
            leafIdx:2,
            proof:[
                bytes32(0x5a9d0f95ad207f61ec6a3d8b2fc68afc3cb13eaaae91f01a481f7c3d069472ad),
                bytes32(0x665a53a7a4158ef85effefadafb70cc2b0f5a2730ba249e394ade1a50a9ff860),
                bytes32(0xf6371c25077974c2103eba464e3d156daf5dd07b5fadc61e4d46a540bbd2a8fc),
                bytes32(0x55ca2a37baea541065c114678849eff535d47e4b6bd1dfdf7b5228f8154ba297),
                bytes32(0x8cb6ca32d6e8f7502de010f7006abb3adc30de603b8ce78338f17087cc5337f4),
                bytes32(0xdc937903ea8463bc3b5d5d955996741b3755738f8db5778f72d2d5935b6d0d1f)
            ]
        });
        storageResponses = new IAxiomV1Query.StorageResponse[](2);
        storageResponses[0] = IAxiomV1Query.StorageResponse({
            blockNumber:0x00e4a8de,
            addr:address(0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03),
            slot:0xc3a24b0501bd2c13a7e57f2db4369ec4c223447539fc0724a9d55ac4a06ebd4d,
            value:0x000000000000000000000000ae7f458667f1b30746354abc3157907d9f6fd15e,
            leafIdx:5,
            proof:[
                bytes32(0x3bcd8b2d335cb29067add168998f15c0e6d95ddb9d5e201d401e209c2e44105a),
                bytes32(0x31997bbbd8a758724d7da2b0cd5124528fe898b5a864d57e04632ccc578917d0),
                bytes32(0x353a3ce929af5ece3c7f40f7eec7aee600e3e9d996bba3cd1036bc179caab6ed),
                bytes32(0x856dd40d86680c29172434871dc7c4658202155123984eba56106f25c3e760dd),
                bytes32(0xa5be3438169bce453d6fea0cea536e017415bb356413bebd02eefa6ad90be79a),
                bytes32(0xaf834e301342cca73396a73b664426a48e4c3220e6af2b824b5813666c853738)
            ]
        });
        storageResponses[1] = IAxiomV1Query.StorageResponse({
            blockNumber:0x00e4a8de,
            addr:address(0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03),
            slot:0x9f4e12e393433b9749089d7660b578840ae05c9423ce1aefceb0c80c340a21c6,
            value:0x00000000000000000000000028d804bf2212e220bc2b7b6252993db8286df07f,
            leafIdx:37,
            proof:[
                bytes32(0xfd88b0196f3238660ba0d6b511c3372c69c552043fe60445e8e51a8bbe894a0b),
                bytes32(0x5303f8e3edb6f5de7d19eceff09ea1987b43a1e4be803509fe15e1ca45a13aa9),
                bytes32(0xad5c6fc4bc7de66d9319cbadf98bb98a2423777a54a9b3dfaf4f2da4e8377010),
                bytes32(0x5d166b5043b1b2af0dabc6a947c56df90844f4de95bd96b8d8cf76106ee77154),
                bytes32(0x132dd3f2c5947e0f8c6a567dfc9baf4743332ba7fd93111892b3a578484efa06),
                bytes32(0x8d9273852e6da2438f32e3b34ee4cd917a595419b856a6984a57968c58c6384a)
            ]
        }); 
    }    

    function testAreResponsesValid_old_success() public {
        testVerifyResultVsMMR_old();

        (IAxiomV1Query.BlockResponse[] memory blockResponses,
         IAxiomV1Query.AccountResponse[] memory accountResponses,
         IAxiomV1Query.StorageResponse[] memory storageResponses) = getResponses();

        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x322d1ad245a73637a4731299672fdf3b6d2608dc223f1669bfdcd306fd304ce9),
            bytes32(0x082df7ffd0116d06a60b47987dd4f6708a2211b976df2d5374aff1614ab6a644),
            bytes32(0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398),
            blockResponses,
            accountResponses,
            storageResponses        
        );
        assert(isValid);
    }   

    function testAreResponsesValid_old_fail_block() public {
        testVerifyResultVsMMR_old();

        (IAxiomV1Query.BlockResponse[] memory blockResponses,
         IAxiomV1Query.AccountResponse[] memory accountResponses,
         IAxiomV1Query.StorageResponse[] memory storageResponses) = getResponses();
        blockResponses[0].blockNumber = 232324;

        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x322d1ad245a73637a4731299672fdf3b6d2608dc223f1669bfdcd306fd304ce9),
            bytes32(0x082df7ffd0116d06a60b47987dd4f6708a2211b976df2d5374aff1614ab6a644),
            bytes32(0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398),
            blockResponses,
            accountResponses,
            storageResponses        
        );
        assert(!isValid);
    }

    function testAreResponsesValid_old_fail_account() public {
        testVerifyResultVsMMR_old();

        (IAxiomV1Query.BlockResponse[] memory blockResponses,
         IAxiomV1Query.AccountResponse[] memory accountResponses,
         IAxiomV1Query.StorageResponse[] memory storageResponses) = getResponses();
        accountResponses[0].nonce = 0x2324;

        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x322d1ad245a73637a4731299672fdf3b6d2608dc223f1669bfdcd306fd304ce9),
            bytes32(0x082df7ffd0116d06a60b47987dd4f6708a2211b976df2d5374aff1614ab6a644),
            bytes32(0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398),
            blockResponses,
            accountResponses,
            storageResponses        
        );
        assert(!isValid);
    }

    function testAreResponsesValid_old_fail_storage() public {
        testVerifyResultVsMMR_old();

        (IAxiomV1Query.BlockResponse[] memory blockResponses,
         IAxiomV1Query.AccountResponse[] memory accountResponses,
         IAxiomV1Query.StorageResponse[] memory storageResponses) = getResponses();
        storageResponses[1].proof[0] = 0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398;

        bool isValid = axiomQuery.areResponsesValid(
            bytes32(0x322d1ad245a73637a4731299672fdf3b6d2608dc223f1669bfdcd306fd304ce9),
            bytes32(0x082df7ffd0116d06a60b47987dd4f6708a2211b976df2d5374aff1614ab6a644),
            bytes32(0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398),
            blockResponses,
            accountResponses,
            storageResponses        
        );
        assert(!isValid);
    }                             

    function setupVerifyOld() public returns (
        IAxiomV1Query.RecentMMRWitness memory mmrWitness
    ) {
        deployRecent();
        axiom.setMMRRingBuffer(2, bytes32(0xbfe45f2d685be849578a95bea4b8b053c63329084db7b06fee20ca2ad3c6556a));
        axiom.setHistoricalRoot(16_525_312, bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923572726));

        bytes32[10] memory recentMMRPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), 
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
        ];
        bytes32[10] memory mmrComplementOrPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
        ];
        mmrWitness = IAxiomV1Query.RecentMMRWitness({
            recentMMRPeaks:recentMMRPeaks,
            mmrComplementOrPeaks:mmrComplementOrPeaks,
            prevHash:bytes32(0x18f917dfb1f2305827190aa16cfb09b942f529da45c2f58e706638821eb0fffd),
            root:bytes32(0x1212ed9e6531665f118d340e31defebcaf7240d557c85bf23bd37e7401be8035),
            numFinal:uint32(888),
            startBlockNumber:uint32(16_525_312)
        });
    }    

    function testVerifyResultVsMMR_old() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyOld();
        vm.expectEmit(false, false, false, true);
        emit KeccakResultEvent(
            bytes32(0x322d1ad245a73637a4731299672fdf3b6d2608dc223f1669bfdcd306fd304ce9),
            bytes32(0x082df7ffd0116d06a60b47987dd4f6708a2211b976df2d5374aff1614ab6a644),
            bytes32(0x33637ca1c7b3c31311cef488b2f31a83c3ab61cbb1e5615b62a460ec032f2398)
        );
        vm.expectEmit(false, false, false, true);
        emit PoseidonResultEvent(
            bytes32(0x2a8a5879fc5648c7be24f15e69eb96c2be738222bfac9581d2c97968be6a18bb),
            bytes32(0x24cc26563ed6861bf3e5bbbacda1c3a2bd92c17deab83c4787132a1e39a1ca40),
            bytes32(0x1f8d632b3e4e554acee7d33597d61a7c1c91778364a23eebac9242c59919a30c)
        );        
        vm.prank(address(111));
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proofOld);
    }

    function setupVerify() public returns (IAxiomV1Query.RecentMMRWitness memory mmrWitness) {
        deployRecent();
        axiom.setMMRRingBuffer(2, bytes32(0xbfe45f2d685be849578a95bea4b8b053c63329084db7b06fee20ca2ad3c6556a));
        axiom.setHistoricalRoot(16_525_312, bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923572726));

        bytes32[10] memory recentMMRPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), 
            bytes32(0x8b3a3edbb630e10137c73c1ed5c97430780ac8eec9d7377d23616b2917266134), 
            bytes32(0xc10835fac9fa70d643de38a49c39d34c15430c14524e655dc254c970cc14613e), 
            bytes32(0x04bf2aed8bebf56f9a7c1d9f09981f5c79a0b36f5cb40b27bd67c40963a06e85), 
            bytes32(0x49f13b9f2d98b9da20760dd5c1d426fa88e7dee5d81830622f5b32a9b476e4a6), 
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), 
            bytes32(0x99f4b8a0bfec3d4981afe8d5e1ca52a180e12ce968ca1174e0dd43b841f3fb6d), 
            bytes32(0x148f3ef4a995b5cf79d74393f3e3aefc6331ca44ccfd715977d6f92cadc7d86d)
        ];
        bytes32[10] memory mmrComplementOrPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
        ];
        mmrWitness = IAxiomV1Query.RecentMMRWitness({
            recentMMRPeaks:recentMMRPeaks,
            mmrComplementOrPeaks:mmrComplementOrPeaks,
            prevHash:bytes32(0x18f917dfb1f2305827190aa16cfb09b942f529da45c2f58e706638821eb0fffd),
            root:bytes32(0x1212ed9e6531665f118d340e31defebcaf7240d557c85bf23bd37e7401be8035),
            numFinal:uint32(888),
            startBlockNumber:uint32(16_525_312)
        });        
    }

    event KeccakResultEvent(bytes32 keccakBlockResponse, bytes32 keccakAccountResponse, bytes32 keccakStorageResponse);
    event PoseidonResultEvent(bytes32 poseidonBlockResponse, bytes32 poseidonAccountResponse, bytes32 poseidonStorageResponse);

    function testVerifyResultVsMMR_inMerkle() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.expectEmit(false, false, false, true);
        emit KeccakResultEvent(
            bytes32(0x434bf7672b7657411e1824edbbea4cb990a1a6ee56d9be0e659774cbe8f956dd),
            bytes32(0xac95e2258648f8f86b3624bbc04b521fdf4b6ff03783b272e9861bff623530c7),
            bytes32(0x7e3cd333fb85a005b3eabed6bfcb2760966650d0a5377a80e3d2ed449f4bb63f)
        );
        vm.expectEmit(false, false, false, true);
        emit PoseidonResultEvent(
            bytes32(0x091ecc3df9cfe52bdbf1bad5c6a7f8aa4416fab9b6a61152692d30d6c510c647),
            bytes32(0x0c79375f0e6e921f718640d65d36b4c0881ef22c9b245769236145725556c5b7),
            bytes32(0x2e1b4dac392cebfa1bbf4bb424a53a798ddaa129e15cc86f46e66630d4d7cb73)
        );        
        vm.prank(address(111));
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_inMerkle_fail_role() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(211));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }    

    function testVerifyResultVsMMR_inMerkle_fail_recentMMR() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        axiom.setMMRRingBuffer(2, bytes32(0xc024ee75f5b6f1057832af572b16c85a24680654e223a18d1335885ee82103b1));
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }        

    function testVerifyResultVsMMR_inMerkle_fail_historicalRoot() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        axiom.setHistoricalRoot(16_525_312, bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923572716));
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }    

    function testVerifyResultVsMMR_inMerkle_fail_historicalRoot2() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        mmrWitness.startBlockNumber = 16_525_312 - 1024;
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_inMerkle_fail_blockHashRoot() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        axiom.setHistoricalRoot(16_525_312, keccak256(abi.encodePacked(
            mmrWitness.prevHash, 
            bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923a22716), 
            mmrWitness.numFinal
        )));
        mmrWitness.root = bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923a22716);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_inMerkle_fail_mmrWitness() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        mmrWitness.mmrComplementOrPeaks[3] = bytes32(0x32bf3ebc821147111c852cc7a74240fdf8586dba69afa07a4856c78923a22716);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }        

    function testVerifyResultVsMMR_inMerkle_fail_proof() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, hex"00");
    }

    function testVerifyResultVsMMR_inMerkle_fail2_proof() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proofTrunc);
    }

    function testVerifyResultVsMMR_inMerkle_fail3_proof() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proofFail);
    }

    function testVerifyResultVsMMR_inMerkle_fail_mmrIdx() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(1, mmrWitness, proof);
    }
    
    function testVerifyResultVsMMR_inMerkle_fail_mmrIdx2() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerify();
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(10, mmrWitness, proof);
    }             

    function setupVerifyAfter() public returns (IAxiomV1Query.RecentMMRWitness memory mmrWitness) {
        deployRecent();
        // MMR up to block 16_525_312
        axiom.setMMRRingBuffer(2, bytes32(0xbfe45f2d685be849578a95bea4b8b053c63329084db7b06fee20ca2ad3c6556a));
        axiom.setHistoricalRoot(16_525_312, bytes32(0x00b6414cd2a463ea2ec0bdfd0e3464bf3c19dcef8b6710fe6efa19e13bde6aa0));

        bytes32[10] memory recentMMRPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), 
            bytes32(0x8b3a3edbb630e10137c73c1ed5c97430780ac8eec9d7377d23616b2917266134), 
            bytes32(0xc10835fac9fa70d643de38a49c39d34c15430c14524e655dc254c970cc14613e), 
            bytes32(0x04bf2aed8bebf56f9a7c1d9f09981f5c79a0b36f5cb40b27bd67c40963a06e85), 
            bytes32(0x49f13b9f2d98b9da20760dd5c1d426fa88e7dee5d81830622f5b32a9b476e4a6), 
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000), 
            bytes32(0x99f4b8a0bfec3d4981afe8d5e1ca52a180e12ce968ca1174e0dd43b841f3fb6d), 
            bytes32(0x148f3ef4a995b5cf79d74393f3e3aefc6331ca44ccfd715977d6f92cadc7d86d)
        ];
        bytes32[10] memory mmrComplementOrPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x1652d5fba64e377c08b07af274c2aea9fb401251362f0f1f2ec9c7545f09bdef),
            bytes32(0xb5f49e0214eddefad32d06cbfd948d389396259672a1ba7d64e09bd28a569dfa),
            bytes32(0xc2757981fcaa38193568a0a01b8efa5453d24664f43d55287a2a908999c2230e),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x04bf2aed8bebf56f9a7c1d9f09981f5c79a0b36f5cb40b27bd67c40963a06e85),
            bytes32(0x49f13b9f2d98b9da20760dd5c1d426fa88e7dee5d81830622f5b32a9b476e4a6),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x99f4b8a0bfec3d4981afe8d5e1ca52a180e12ce968ca1174e0dd43b841f3fb6d),
            bytes32(0x148f3ef4a995b5cf79d74393f3e3aefc6331ca44ccfd715977d6f92cadc7d86d)
        ];
        mmrWitness = IAxiomV1Query.RecentMMRWitness({
            recentMMRPeaks:recentMMRPeaks,
            mmrComplementOrPeaks:mmrComplementOrPeaks,
            prevHash:bytes32(0x18f917dfb1f2305827190aa16cfb09b942f529da45c2f58e706638821eb0fffd),
            root:bytes32(0x140d11b6d6d4f6147a415f4ccd610081e081a6758d59e924b3700fae8207e71d),
            numFinal:uint32(878),
            startBlockNumber:uint32(16_525_312)
        });
    }

    function testVerifyResultVsMMR_afterMerkle() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        vm.prank(address(111));
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_afterMerkle_fail_notRecent() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        vm.roll(16_525_312 + 800);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }     

    function testVerifyResultVsMMR_afterMerkle_fail_notRecent2() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        vm.roll(16_525_312 + 2000);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_afterMerkle_fail_mmrComplementOrPeaks() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        mmrWitness.mmrComplementOrPeaks[1] = bytes32(0x0);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_afterMerkle_fail_mmrComplementOrPeaks2() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        mmrWitness.mmrComplementOrPeaks[1] = bytes32(0x12f13b9f2d98b9da20760dd5c1d426fa88e7dee5d81830622f5b32a9b476e4a6);
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_afterMerkle_fail_recentMMR() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        mmrWitness.mmrComplementOrPeaks = [
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0xd6a86147728bce5a6ea7c2ae22e1cc6a707004fb5673359b11803680287054e7),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x20f09125160825a7cba452e65aa55075daab16987efa4f37493f1bcb2e8671b9),
            bytes32(0xb6277c130610ee3f7889222df96638f737cf95211ee419f35341bf9286c2b6ef)
        ];        
        mmrWitness.startBlockNumber = 16_525_312;
        mmrWitness.root = bytes32(0xfde3754319f453bac77337bc80a6a72ca076a5c5511178ac6c6e3b598d065959);
        mmrWitness.numFinal = 800;
        axiom.setHistoricalRoot(16_525_312, keccak256(abi.encodePacked(mmrWitness.prevHash, mmrWitness.root, mmrWitness.numFinal)));
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }

    function testVerifyResultVsMMR_afterMerkle_fail_recentMMR2() public {
        IAxiomV1Query.RecentMMRWitness memory mmrWitness = setupVerifyAfter();
        mmrWitness.mmrComplementOrPeaks = [
            bytes32(0xd233f5988996b4050826e708679e5f72b88d33942a5dbde3fa5c052852958b99),
            bytes32(0xcc2f5ad7186c1ba0042162ea0068e45ad2e47b66176a86e845c0a133e46fa953),
            bytes32(0x9ba2c722652c63cd688724169b4ab519302f63ff0f105ccd94d0e95b84a4d373),
            bytes32(0xb8c83a8f5ab3f19ef8d696cdb7d54adaf2a64b66fc184e24dfab00bb671c3f7f),
            bytes32(0x4aaffe85b9fc9698cda21b02d4740cb74dca814a3ca0343f459336a632b05f46),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x8732e5911479582067e24f564643c5602174232ae7881b74548c0401a7fadff7),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
            bytes32(0x20f09125160825a7cba452e65aa55075daab16987efa4f37493f1bcb2e8671b9),
            bytes32(0xb6277c130610ee3f7889222df96638f737cf95211ee419f35341bf9286c2b6ef)
        ];        
        mmrWitness.startBlockNumber = 16_525_312;
        mmrWitness.root = bytes32(0xa0f4ed713b7fbc44f03c3fccb470724d35f9437bce3a7b2a9e666624b5e84cc3);
        mmrWitness.numFinal = 863;
        axiom.setHistoricalRoot(16_525_312, keccak256(abi.encodePacked(mmrWitness.prevHash, mmrWitness.root, mmrWitness.numFinal)));
        vm.prank(address(111));
        vm.expectRevert();
        axiomQuery.verifyResultVsMMR(2, mmrWitness, proof);
    }                                                
}
