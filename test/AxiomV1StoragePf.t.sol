// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "./AxiomV1.t.sol";
import "../contracts/AxiomV1StoragePf.sol";
import "../lib/YulDeployer.sol";

uint32 constant testBlockNumber = 16329190;
uint32 constant testPrevBlockNumber = 16328704;
bytes32 constant testBlockHash = bytes32(hex"eaa53f3fbfe912c45af96f4a1a34e3cb1de8e9ac1b6fe8d8b1c9eadad976eda9");
bytes32 constant testPrevHash = bytes32(hex"87445763da0b6836b89b8189c4fe71861987aa9af5a715bfb222a7978d98630d");
bytes32 constant testRoot = bytes32(hex"94768cc8e722c0dfa1be6e2326573764102b7a80685a3e98d340ab121e7277cd");
address constant testAddress = 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB;
uint32 constant testNumFinal = 0;

contract AxiomStoragePfTest is Test {
    AxiomV1Cheat public axiom;
    AxiomV1StoragePf private implementationSt = new AxiomV1StoragePf();
    AxiomV1StoragePf public axiomStorage;
    YulDeployer yulDeployer;

    address axiomVerifierAddress;
    address storageVerifierAddress;

    bytes proof;
    bytes32[10] blockMerkleProof;
    IAxiomV1Verifier.BlockHashWitness blockData;

    function setUp() public {
        yulDeployer = new YulDeployer();
        // `mainnet_10_7.v0.1` is a Yul verifier for a SNARK constraining a chain of up to 1024 block headers
        // and Merkle-ization of their block hashes as specified in `updateRecent`.
        axiomVerifierAddress = address(yulDeployer.deployContract("v0/mainnet_10_7.v0.1"));
        // `storage_ts.v0.1` is a Yul verifier for a SNARK constraining 10 storage proofs into a single account
        // as specified in `attestSlots`.
        storageVerifierAddress = address(yulDeployer.deployContract("v0/storage_ts.v0.1"));
        vm.makePersistent(axiomVerifierAddress);
        vm.makePersistent(storageVerifierAddress);
        vm.makePersistent(address(implementationSt));

        // valid SNARK for `attestSlots`
        proof = vm.parseBytes(vm.readFile("test/data/v0/storage.calldata"));
        blockMerkleProof = [
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
        blockData = IAxiomV1Verifier.BlockHashWitness({
            blockNumber: testBlockNumber,
            claimedBlockHash: testBlockHash,
            prevHash: testPrevHash,
            numFinal: testNumFinal,
            merkleProof: blockMerkleProof
        });
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
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            address(axiom),
            storageVerifierAddress,
            address(1),
            address(3)
        );
        AxiomProxy proxySt = new AxiomProxy(address(implementationSt), data);
        axiomStorage = AxiomV1StoragePf(payable(address(proxySt)));
        // vm.resumeGasMetering();
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
            "initialize(address,address,address,address)", address(0), storageVerifierAddress, address(1), address(3)
        );
        vm.expectRevert();
        AxiomProxy proxySt = new AxiomProxy(address(implementationSt), data);
        axiomStorage = AxiomV1StoragePf(payable(address(proxySt)));
    }

    function testInit_zeroVerifierAddress() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", address(axiom), address(0), address(1), address(3)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementationSt), data);
    }

    function testInit_zeroTimelockAddress() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            address(axiom),
            storageVerifierAddress,
            address(0),
            address(3)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementationSt), data);
    }

    function testInit_zeroGuardianAddress() public {
        AxiomV1Cheat implementation = new AxiomV1Cheat();
        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", axiomVerifierAddress, address(1), address(2), address(3)
        );
        AxiomProxy proxy = new AxiomProxy(address(implementation), data);
        axiom = AxiomV1Cheat(payable(address(proxy)));
        axiom.setHistoricalRoot(testPrevBlockNumber, keccak256(abi.encodePacked(testPrevHash, testRoot, testNumFinal)));
        axiom = AxiomV1Cheat(payable(address(proxy)));

        data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            address(axiom),
            storageVerifierAddress,
            address(1),
            address(0)
        );
        vm.expectRevert();
        new AxiomProxy(address(implementationSt), data);
    }

    function testAttestSlots() public {
        deploy();

        axiomStorage.attestSlots(blockData, proof);
        assert(
            axiomStorage.slotAttestations(
                keccak256(abi.encodePacked(testBlockNumber, testAddress, uint256(0), uint256(129)))
            )
        );
        assert(
            !axiomStorage.slotAttestations(
                keccak256(abi.encodePacked(testBlockNumber, testAddress, uint256(1), uint256(129)))
            )
        );
        assert(
            !axiomStorage.slotAttestations(
                keccak256(abi.encodePacked(testBlockNumber, testAddress, uint256(0), uint256(128)))
            )
        );
    }

    function testAttestSlots_blockHash_witness_fail() public {
        deploy();
        blockData.claimedBlockHash = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proof);
    }

    function testAttestSlots_blockNumber_witness_fail() public {
        deploy();
        blockData.blockNumber = 1232;
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proof);
    }

    function testAttestSlots_proof_fail() public {
        deploy();
        bytes memory proofFail = vm.parseBytes(vm.readFile("test/data/v0/storage.fail.calldata"));
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proofFail);
    }

    function testAttestSlots_blockHash_fail() public {
        deploy();
        bytes memory proofFail = vm.parseBytes(vm.readFile("test/data/v0/storage.fail.blockHash.calldata"));
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proofFail);
    }

    function testAttestSlots_blockNumber_fail() public {
        deploy();
        bytes memory proofFail = vm.parseBytes(vm.readFile("test/data/v0/storage.fail.blockNumber.calldata"));
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proofFail);
    }

    function testAttestSlots_recentInvalid() public {
        deploy();
        blockData.blockNumber = 16428704 - 10;
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proof);
    }

    function testAttestSlots_oldInvalid() public {
        deploy();
        blockData.merkleProof[0] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proof);
    }

    function testAttestSlots_frozen() public {
        deploy();

        vm.prank(address(3));
        axiomStorage.freezeAll();
        vm.expectRevert();
        axiomStorage.attestSlots(blockData, proof);
    }

    function testIsSlotAttestationValid() public {
        testAttestSlots();
        assert(axiomStorage.isSlotAttestationValid(testBlockNumber, testAddress, uint256(0), uint256(129)));
        assert(!axiomStorage.isSlotAttestationValid(testBlockNumber, testAddress, uint256(0), uint256(128)));
    }

    function testIsSlotAttestationValid_frozen() public {
        testAttestSlots();
        vm.prank(address(3));
        axiomStorage.freezeAll();
        vm.expectRevert();
        axiomStorage.isSlotAttestationValid(testBlockNumber, testAddress, uint256(0), uint256(129));
    }

    function testAttestSlotsForkRecent() public {
        string memory MAINNET_RPC_URL = string.concat("https://mainnet.infura.io/v3/", vm.envString("INFURA_ID"));
        vm.createSelectFork(MAINNET_RPC_URL, 16_509_500);

        bytes32[10] memory blockProof = [
            bytes32(0x33d28805ae6da649df58d72a8246644d8d846334e36402d945222374b574563f),
            bytes32(0x0569f9a4a837ec1ec1a8e011d259820621f550ce214d642d5a5a173bd7f4fede),
            bytes32(0xfee8347b64953efc8a75b7405f6fbf5b1e1da7ea8db1f4140a248410e3733749),
            bytes32(0xee9b2c774e9bb9cc4d0f4ce72f6754739d64ba4c8cc58d7d3f149123a73fcaeb),
            bytes32(0xb63bb5b8fc535af9b4fa6d428293f78bf12c7ef363a8fbcc452970f122364e2e),
            bytes32(0x5e1e1248e32c2a1c457affcf97e9de873bcc5c625193ef9a37aae9b14d597aa2),
            bytes32(0xcffb84a2e8c15c129d28a8d86170e116ed6df6546f7869da2cd4c54ebc368ce7),
            bytes32(0x727cf857104096d05f0194449102ae2b465c2b16688d91386a04237433fc02b4),
            bytes32(0x8a1984156eed6a4ca136b8780474dc6d8a10870dd584afa2792ebbd3aa9d1525),
            bytes32(0xaddd0eeabdf3cc15032ee991d415914a74cad3a36eb989615041be7a8049c5dd)
        ];
        address AXIOM_ADDRESS = 0x01d5b501C1fc0121e1411970fb79c322737025c2;

        // Valid SNARK verified against a recent block hash
        string memory mainnetPath = "test/data/v0/storage_mainnet_recent.calldata";
        string memory bashCmd = string.concat('cast abi-encode "f(bytes)" $(cat ', string.concat(mainnetPath, ")"));
        string[] memory inp = new string[](3);
        inp[0] = "bash";
        inp[1] = "-c";
        inp[2] = bashCmd;
        bytes memory mainnetProof = abi.decode(vm.ffi(inp), (bytes));

        IAxiomV1Verifier.BlockHashWitness memory bd = IAxiomV1Verifier.BlockHashWitness({
            blockNumber: 16509490,
            claimedBlockHash: bytes32(0xd30083d9e5dca72831830c53dec1c7fa4e313ca2648f607e049f3d72ea4a3171),
            prevHash: bytes32(0xf21f9ac46b21ce128bf245ac8c5dcd12ab1bf6a0cb0e3c7dc4d33cc8871d8ab3),
            numFinal: 1024,
            merkleProof: blockProof
        });

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)", AXIOM_ADDRESS, storageVerifierAddress, address(1), address(3)
        );
        AxiomProxy proxySt = new AxiomProxy(address(implementationSt), data);
        emit log_address(address(proxySt));
        AxiomV1StoragePf sp = AxiomV1StoragePf(payable(address(proxySt)));

        sp.attestSlots(bd, mainnetProof);
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16509490),
                        AXIOM_ADDRESS,
                        uint256(0),
                        uint256(1375236228069028149185275772995843645681337161775)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16509490),
                        AXIOM_ADDRESS,
                        uint256(1),
                        uint256(1091398976428249091872878358812344116603181475905)
                    )
                )
            )
        );
    }

    function testAttestSlotsForkProof() public {
        string memory MAINNET_RPC_URL = string.concat("https://mainnet.infura.io/v3/", vm.envString("INFURA_ID"));
        vm.createSelectFork(MAINNET_RPC_URL, 16_510_306);

        bytes32[10] memory blockProof = [
            bytes32(0x751e47c2f3e4b6a78a96777b225ae2805e05258ee82cc2da0add2ee7c0417b8c),
            bytes32(0x996b11080554f6f21d9ed3434f8a5957c2d2b750c15264bb9bf323d7f829560e),
            bytes32(0x6ae7e0a7d08aa440939d471cd506f989d07bc60ba9a9dae26b4c422badb004e9),
            bytes32(0xd33bb7bf88dc44a41804627c34e173f76473587479dfb028537e62b400c4c41f),
            bytes32(0xca66db204ba5853df44b12725a7100de1aa7d8aec92c3dc7062361debe5c0d23),
            bytes32(0xcedb7add23c59801c6b58ce02290115078b60476189c991aed9c5849a690a8b1),
            bytes32(0xa0bc4a548dd44b38a021bb3c618319beb01cd0d2e2028cce7001a68345fb2fd5),
            bytes32(0x822fff17d8c65bdc471dcd29ba8ed02a67b33a5dce5430a28ed6957861af2b29),
            bytes32(0xa56bd8ea50542c4fa12894918802d0a95d23087b797ddd92f86ca7c273bd925d),
            bytes32(0x18b964e62d09302855bf275479def5ccd0e27a7201f4613c9fe28705cdf12365)
        ];
        address AXIOM_ADDRESS = 0x01d5b501C1fc0121e1411970fb79c322737025c2;

        // Valid SNARK verified against a previous block hash
        string memory mainnetPath = "test/data/v0/storage_mainnet.calldata";
        string memory bashCmd = string.concat('cast abi-encode "f(bytes)" $(cat ', string.concat(mainnetPath, ")"));
        string[] memory inp = new string[](3);
        inp[0] = "bash";
        inp[1] = "-c";
        inp[2] = bashCmd;
        bytes memory mainnetProof = abi.decode(vm.ffi(inp), (bytes));

        IAxiomV1Verifier.BlockHashWitness memory bd = IAxiomV1Verifier.BlockHashWitness({
            blockNumber: 16508329,
            claimedBlockHash: bytes32(0xf4e3de9f45a8c400a6b9149265a53eef14c25dc9c76c17eb5eb978e94bbe36f1),
            prevHash: bytes32(0xf681d907f5c8cc1e5f3e3d01e080c5d6da0f6b7d3a8853d0ac2afbb542eac2df),
            numFinal: 1024,
            merkleProof: blockProof
        });

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,address)",
            AXIOM_ADDRESS,
            storageVerifierAddress,
            address(1),
            new address[](0)
        );
        AxiomProxy proxySt = new AxiomProxy(address(implementationSt), data);
        AxiomV1StoragePf sp = AxiomV1StoragePf(payable(address(proxySt)));

        sp.attestSlots(bd, mainnetProof);
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329), 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB, uint256(0), uint256(129)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329),
                        0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB,
                        uint256(1),
                        uint256(1115097646744709172646763196234948672627422061930)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329),
                        0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB,
                        uint256(2),
                        uint256(30507219563547590090865375882545948736665079558820606342401593436557467975702)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329),
                        0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB,
                        uint256(3),
                        uint256(30450458735490133573949669185319218724679869604813616774885074089929806446614)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329),
                        0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB,
                        uint256(4),
                        uint256(93964460599044035415898927684509892508737248603639167430823260997144104927236)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329), 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB, uint256(6), uint256(10000)
                    )
                )
            )
        );
        assert(
            sp.slotAttestations(
                keccak256(
                    abi.encodePacked(
                        uint32(16508329), 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB, uint256(8), uint256(1)
                    )
                )
            )
        );
    }

    function testSupportsInterface() public {
        deploy();
        assert(axiomStorage.supportsInterface(type(IAxiomV1StoragePf).interfaceId));
    }

    event UpdateAxiomAddress(address addr);

    function testUpdateAxiomAddress() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateAxiomAddress(address(100));

        axiomStorage.updateAxiomAddress(address(100));
    }

    function testUpdateAxiomAddress_fail() public {
        deploy();
        vm.prank(address(10));
        vm.expectRevert();
        axiomStorage.updateAxiomAddress(address(100));
    }

    event UpdateSnarkVerifierAddress(address addr);

    function testUpdateSnarkVerifierAddress() public {
        deploy();
        vm.prank(address(1));
        vm.expectEmit(false, false, false, true);
        emit UpdateSnarkVerifierAddress(address(100));

        axiomStorage.updateSnarkVerifierAddress(address(100));
    }

    function testUpdateSnarkVerifierAddress_fail() public {
        deploy();
        vm.prank(address(10));
        vm.expectRevert();
        axiomStorage.updateSnarkVerifierAddress(address(100));
    }
}
