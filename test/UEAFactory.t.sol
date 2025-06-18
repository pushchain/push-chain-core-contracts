// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/libraries/Types.sol";
import {Target} from "../src/mocks/Target.sol";
import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {IUEA} from "../src/Interfaces/IUEA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UEAFactoryTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_EVM ueaEVMImpl;
    UEA_SVM ueaSVMImpl;

    address deployer;
    address nonOwner;

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerBytes;

    address verifierPrecompile;

    // VM Hash constants
    bytes32 constant EVM_HASH = keccak256("EVM");
    bytes32 constant SVM_HASH = keccak256("SVM");
    bytes32 constant MOVE_VM_HASH = keccak256("MOVE_VM");
    bytes32 constant WASM_VM_HASH = keccak256("WASM_VM");
    bytes32 constant CAIRO_VM_HASH = keccak256("CAIRO_VM");

    // Set up the test environment - NON-EVM
    bytes ownerNonEVM;
    string solanaChainId;
    string solanaAddress;

    // Chain hashes
    bytes32 ethereumChainHash;
    bytes32 solanaChainHash;

    function setUp() public {
        target = new Target();
        deployer = address(this);
        nonOwner = makeAddr("nonOwner");

        // Deploy implementations for different VM types
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();

        // Deploy the factory implementation
        UEAFactoryV1 factoryImpl = new UEAFactoryV1();

        // Deploy and initialize the proxy
        bytes memory initData = abi.encodeWithSelector(UEAFactoryV1.initialize.selector, deployer);
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(proxy));

        // Set up user and keys
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        // Set up verifier precompile
        verifierPrecompile = 0x0000000000000000000000000000000000000902;

        ownerNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
        solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

        // Store chain hashes for reuse
        ethereumChainHash = keccak256(abi.encode("ETHEREUM"));
        solanaChainHash = keccak256(abi.encode("SOLANA"));

        // Register chains
        factory.registerNewChain(ethereumChainHash, EVM_HASH);
        factory.registerNewChain(solanaChainHash, SVM_HASH);

        // Register implementations
        factory.registerUEA(ethereumChainHash, EVM_HASH, address(ueaEVMImpl));
        factory.registerUEA(solanaChainHash, SVM_HASH, address(ueaSVMImpl));
    }

    function testRegisterNewChain() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Verify the chain was registered
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(vmHash, EVM_HASH);
        assertTrue(isRegistered);
    }

    function testRegisterUEA() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);
        factory.registerUEA(chainHash, EVM_HASH, address(ueaEVMImpl));

        // Check that the UEA implementation is registered
        assertEq(factory.getUEA(chainHash), address(ueaEVMImpl));
    }

    function testRegisterMultipleUEA() public {
        bytes32[] memory chainHashes = new bytes32[](2);
        bytes32[] memory vmHashes = new bytes32[](2);
        address[] memory implementations = new address[](2);

        // Use different chains than those in setUp
        chainHashes[0] = keccak256(abi.encode("KOVAN"));
        chainHashes[1] = keccak256(abi.encode("METIS"));

        vmHashes[0] = EVM_HASH;
        vmHashes[1] = EVM_HASH;

        implementations[0] = address(ueaEVMImpl);
        implementations[1] = address(ueaEVMImpl);

        // Register chains first
        factory.registerNewChain(chainHashes[0], vmHashes[0]);
        factory.registerNewChain(chainHashes[1], vmHashes[1]);

        // Register UEAs in batch
        factory.registerMultipleUEA(chainHashes, vmHashes, implementations);

        // Verify registrations
        assertEq(factory.getUEA(chainHashes[0]), implementations[0]);
        assertEq(factory.getUEA(chainHashes[1]), implementations[1]);
    }

    function testRevertWhenRegisteringSameChainTwice() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register the same chain again
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerNewChain(chainHash, EVM_HASH);
    }

    function testRevertWhenRegisteringZeroAddressUEA() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register zero address as UEA
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(0));
    }

    function testRevertWhenRegisteringUEAWithWrongVMHash() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register UEA with wrong VM hash
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, SVM_HASH, address(ueaEVMImpl));
    }

    function testRevertWhenRegisteringUEAWithUnregisteredChain() public {
        bytes32 chainHash = keccak256(abi.encode("UNREGISTERED"));

        // Try to register UEA for unregistered chain
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(ueaEVMImpl));
    }

    function testRevertWhenRegisteringMultipleUEAWithMismatchedArrays() public {
        bytes32[] memory chainHashes = new bytes32[](2);
        bytes32[] memory vmHashes = new bytes32[](2);
        address[] memory implementations = new address[](1); // Mismatched length

        // Register chains first (use different chains than in setUp)
        chainHashes[0] = keccak256(abi.encode("KOVAN"));
        chainHashes[1] = keccak256(abi.encode("METIS"));

        factory.registerNewChain(chainHashes[0], EVM_HASH);
        factory.registerNewChain(chainHashes[1], EVM_HASH);

        // Try to register with mismatched array lengths
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerMultipleUEA(chainHashes, vmHashes, implementations);
    }

    function testDeployUEA() public {
        // Use ETHEREUM chain which is already registered in setUp
        bytes memory ownerBytes = abi.encodePacked(makeAddr("newowner"));
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);
        assertTrue(factory.hasCode(ueaAddress));

        // Check the owner
        (UniversalAccount memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(abi.encode(retrievedAccount.chain)), keccak256(abi.encode(_id.chain)));
        assertEq(keccak256(retrievedAccount.owner), keccak256(_id.owner));
        assertTrue(isUEA);
    }

    function testRevertWhenDeployingUEAForUnregisteredChain() public {
        bytes memory ownerBytes = abi.encodePacked(makeAddr("owner"));
        UniversalAccount memory _id = UniversalAccount({chain: "UNREGISTERED", owner: ownerBytes});

        // Try to deploy UEA for unregistered chain
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testRevertWhenDeployingUEAWithNoImplementation() public {
        // Register chain but no implementation
        bytes32 chainHash = keccak256(abi.encode("NEW_CHAIN"));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        bytes memory ownerBytes = abi.encodePacked(makeAddr("owner"));
        UniversalAccount memory _id = UniversalAccount({chain: "NEW_CHAIN", owner: ownerBytes});

        // Try to deploy UEA with no implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testRevertWhenDeployingSameUEATwice() public {
        // Use a new owner with ETHEREUM chain
        bytes memory ownerBytes = abi.encodePacked(makeAddr("uniqueowner"));
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        factory.deployUEA(_id);

        // Try to deploy the same UEA again
        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    function testComputeUEA() public {
        // Use ETHEREUM chain which is already registered in setUp
        bytes memory ownerBytes = abi.encodePacked(makeAddr("uniquecomputeowner"));
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address computedAddress = factory.computeUEA(_id);
        assertTrue(computedAddress != address(0));

        // Deploy UEA and check if it matches the computed address
        address deployedAddress = factory.deployUEA(_id);
        assertEq(deployedAddress, computedAddress);
    }

    function testGetUEAForOrigin() public {
        // Use ETHEREUM chain which is already registered in setUp
        bytes memory ownerBytes = abi.encodePacked(makeAddr("uniquegetowner"));
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        // Test for non-deployed UEA
        (address uea, bool isDeployed) = factory.getUEAForOrigin(_id);
        assertTrue(uea != address(0));
        assertFalse(isDeployed);

        // Deploy UEA
        address deployedAddress = factory.deployUEA(_id);

        // Test for deployed UEA
        (address uea2, bool isDeployed2) = factory.getUEAForOrigin(_id);
        assertEq(uea2, deployedAddress);
        assertTrue(isDeployed2);
    }

    function testSwapImplementation() public {
        // Use ETHEREUM chain which is already registered in setUp
        address initialImpl = factory.getUEA(ethereumChainHash);

        // Deploy a new implementation
        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(ethereumChainHash, EVM_HASH, address(newImpl));

        // Check that the implementation was updated
        assertNotEq(factory.getUEA(ethereumChainHash), initialImpl);
        assertEq(factory.getUEA(ethereumChainHash), address(newImpl));
    }

    function testMultipleOwners() public {
        // Create two different owners for ETHEREUM chain
        (address owner1, uint256 owner1PK) = makeAddrAndKey("owner1");
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");

        bytes memory ownerBytes1 = abi.encodePacked(owner1);
        bytes memory ownerBytes2 = abi.encodePacked(owner2);

        UniversalAccount memory account1 = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes1});
        UniversalAccount memory account2 = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes2});

        // Compute UEA addresses
        address computedUEA1 = factory.computeUEA(account1);
        address computedUEA2 = factory.computeUEA(account2);

        // Make sure they're different
        assertNotEq(computedUEA1, computedUEA2);
    }

    function testMultipleDeployments() public {
        // Deploy 10 UEAs for ETHEREUM chain
        for (uint256 i = 0; i < 10; i++) {
            (address testOwner, uint256 testOwnerPK) = makeAddrAndKey(string(abi.encodePacked("testOwner", i)));
            bytes memory ownerBytes = abi.encodePacked(testOwner);
            UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

            address ueaAddress = factory.deployUEA(_id);
            assertTrue(factory.hasCode(ueaAddress));
            
            (UniversalAccount memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
            assertEq(keccak256(retrievedAccount.owner), keccak256(ownerBytes));
            assertTrue(isUEA);
        }
    }

    function testUEAOwnerChange() public {
        // Deploy UEA for original owner on ETHEREUM chain
        bytes memory ownerBytes = abi.encodePacked(makeAddr("originalOwner"));
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);

        // Create a new owner
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerBytes = abi.encodePacked(newOwner);
        UniversalAccount memory newAccount = UniversalAccount({chain: "ETHEREUM", owner: newOwnerBytes});

        // The owner mapping can't be changed - a new UEA would need to be deployed
        (UniversalAccount memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(retrievedAccount.owner), keccak256(ownerBytes));
        assertEq(keccak256(abi.encode(retrievedAccount.chain)), keccak256(abi.encode(_id.chain)));
        assertTrue(isUEA);

        // Deploy UEA for new owner - this should be a different address
        address newUEAAddress = factory.deployUEA(newAccount);
        assertNotEq(ueaAddress, newUEAAddress);
        (UniversalAccount memory newRetrievedAccount, bool isNewUEA) = factory.getOriginForUEA(newUEAAddress);
        assertEq(keccak256(newRetrievedAccount.owner), keccak256(newOwnerBytes));
        assertEq(keccak256(abi.encode(newRetrievedAccount.chain)), keccak256(abi.encode(newAccount.chain)));
        assertTrue(isNewUEA);
    }

    function testOwnershipFunctions() public {
        // Test that only owner can register implementations
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));

        bytes32 chainHash = keccak256(abi.encode("APTOS"));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // Test that owner can register implementations
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(chainHash, MOVE_VM_HASH, address(newImpl));

        // Verify the implementation was registered
        assertEq(address(factory.getUEA(chainHash)), address(newImpl));
    }

    function testDeploymentCreate2() public {
        UniversalAccount memory _id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);
        bytes32 salt = factory.generateSalt(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(salt)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    function testComputeUEAAddressNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({chain: "SOLANA", owner: ownerNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    function testMissingImplementation() public {
        bytes32 moveChainHash = keccak256(abi.encode("APTOS"));
        factory.registerNewChain(moveChainHash, MOVE_VM_HASH);

        // Create an UniversalAccount with VM type that has no implementation
        UniversalAccount memory _id = UniversalAccount({chain: "APTOS", owner: ownerBytes});

        // Try to deploy with missing implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testMultipleChainsSameVM() public {
        // Register two different chains with the same VM type (EVM)
        bytes32 ethereumChainHash = keccak256(abi.encode("ETHEREUM"));
        bytes32 polygonChainHash = keccak256(abi.encode("POLYGON"));

        // Polygon is not registered yet
        factory.registerNewChain(polygonChainHash, EVM_HASH);

        // We already registered EVM implementation for Ethereum, should work for Polygon too
        (bytes32 vmHashEth, bool isRegisteredEth) = factory.getVMType(ethereumChainHash);
        (bytes32 vmHashPoly, bool isRegisteredPoly) = factory.getVMType(polygonChainHash);

        // Verify both chains use the same VM type
        assertEq(vmHashEth, vmHashPoly);
        assertTrue(isRegisteredEth);
        assertTrue(isRegisteredPoly);

        // Both chains should use the same implementation
        assertEq(factory.getUEA(ethereumChainHash), factory.getUEA(polygonChainHash));

        // Deploy UEAs for both chains and verify they have different addresses despite same VM
        UniversalAccount memory ethAccount = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        UniversalAccount memory polyAccount = UniversalAccount({chain: "POLYGON", owner: ownerBytes});

        address ethUEA = factory.deployUEA(ethAccount);

        // Need a different owner key for the second account since same owner key can't be used twice
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        polyAccount.owner = owner2Key;
        address polyUEA = factory.deployUEA(polyAccount);

        // Addresses should be different despite same VM type
        assertTrue(ethUEA != polyUEA);
    }

    function testOwnershipTransfer() public {
        address newOwner = makeAddr("newOwner");

        // Transfer ownership to new owner
        factory.transferOwnership(newOwner);

        // Verify new owner
        assertEq(factory.owner(), newOwner);

        // Try to register a chain with old owner, should fail
        bytes32 chainHash = keccak256(abi.encode("TestChain"));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // New owner should be able to register a chain
        vm.prank(newOwner);
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // Verify chain is registered
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(vmHash, MOVE_VM_HASH);
        assertTrue(isRegistered);
    }

    function testFactoryLifecycle() public {
        // Create multiple owners
        address[] memory owners = new address[](5);
        bytes[] memory ownerValues = new bytes[](5);

        for (uint256 i = 0; i < 5; i++) {
            (owners[i],) = makeAddrAndKey(string(abi.encodePacked("owner", i)));
            ownerValues[i] = abi.encodePacked(owners[i]);
        }

        // Register multiple chains
        string[] memory chains = new string[](3);
        chains[0] = "ETHEREUM"; // Ethereum
        chains[1] = "POLYGON"; // Polygon
        chains[2] = "BSC"; // BSC

        // Register chains that aren't already registered
        for (uint256 i = 1; i < 3; i++) {
            bytes32 chainHash = keccak256(abi.encode(chains[i]));
            // Check if chain is already registered
            (, bool isRegistered) = factory.getVMType(chainHash);
            if (!isRegistered) {
                factory.registerNewChain(chainHash, EVM_HASH);
            }
        }

        // Deploy accounts for different combinations
        address[] memory deployedUEAs = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            string memory chain = chains[i % 3]; // Cycle through chains

            UniversalAccount memory account = UniversalAccount({chain: chain, owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);

            deployedUEAs[i] = factory.deployUEA(account);

            // Verify mappings are consistent
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
            (UniversalAccount memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(deployedUEAs[i]);
            assertEq(keccak256(retrievedAccount.owner), keccak256(ownerValues[i]));
            assertEq(keccak256(abi.encode(retrievedAccount.chain)), keccak256(abi.encode(chain)));
            assertTrue(isUEA);
        }

        // Verify all deployed accounts are retrievable
        for (uint256 i = 0; i < 5; i++) {
            UniversalAccount memory account = UniversalAccount({chain: chains[i % 3], owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
        }
    }

    function testChainConfigChanges() public {
        // Create a new chain and register it
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Deploy an account with the initial implementation
        UniversalAccount memory account = UniversalAccount({chain: "KOVAN", owner: ownerBytes});

        // Get initial implementation address
        address initialImpl = factory.getUEA(chainHash);

        // Deploy a UEA with the initial implementation
        address initialUEA = factory.deployUEA(account);

        // Deploy a new implementation
        UEA_EVM newImpl = new UEA_EVM();

        // Change implementation for EVM type
        bytes32 evmChainHash = keccak256(abi.encode("ETHEREUM"));
        factory.registerUEA(evmChainHash, EVM_HASH, address(newImpl));

        // Verify implementation has changed
        address updatedImpl = factory.getUEA(chainHash);
        assertEq(updatedImpl, address(newImpl));

        // Verify the change impacts new deployments but not existing ones
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        UniversalAccount memory account2 = UniversalAccount({chain: "KOVAN", owner: owner2Key});

        // Compute address with new implementation
        address newUEAAddress = factory.computeUEA(account2);

        // Old UEA still exists and isn't affected
        assertTrue(factory.hasCode(initialUEA));
    }

    function testMappingConsistency() public {
        // Deploy a UEA
        UniversalAccount memory account = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);

        // Test getOriginForUEA
        (UniversalAccount memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(retrievedAccount.owner), keccak256(ownerBytes));
        assertEq(keccak256(abi.encode(retrievedAccount.chain)), keccak256(abi.encode(account.chain)));
        assertTrue(isUEA);

        // Test getUEAForOrigin
        (address retrievedUEA, bool isDeployed) = factory.getUEAForOrigin(account);
        assertEq(retrievedUEA, ueaAddress);
        assertTrue(isDeployed);

        // Test with non-existent UEA
        address randomAddr = makeAddr("random");
        (UniversalAccount memory randomAccount, bool isRandomUEA) = factory.getOriginForUEA(randomAddr);
        assertFalse(isRandomUEA);
        assertEq(randomAccount.owner.length, 0);
        assertEq(bytes(randomAccount.chain).length, 0);

        // Test with non-existent owner key but predictable address
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerKey = abi.encodePacked(newOwner);

        UniversalAccount memory newAccount = UniversalAccount({chain: "ETHEREUM", owner: newOwnerKey});

        // Compute without deploying
        address computedAddress = factory.computeUEA(newAccount);

        // Verify getUEAForOrigin returns computed address but shows not deployed
        (address predictedAddress, bool isNewDeployed) = factory.getUEAForOrigin(newAccount);
        assertEq(predictedAddress, computedAddress);
        assertFalse(isNewDeployed);
    }

    function testHasCode() public {
        // Contract address should have code
        assertTrue(factory.hasCode(address(factory)));

        // EOA should not have code
        assertFalse(factory.hasCode(address(0x123)));

        // Newly deployed UEA should have code
        UniversalAccount memory account = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);
        assertTrue(factory.hasCode(ueaAddress));
    }

    function testDifferentOwnerKeysSameChain() public {
        // Create two different owner keys
        bytes memory owner1Key = abi.encodePacked(makeAddr("owner1"));
        bytes memory owner2Key = abi.encodePacked(makeAddr("owner2"));

        // Create accounts for the same chain but different owners
        UniversalAccount memory account1 = UniversalAccount({chain: "ETHEREUM", owner: owner1Key});
        UniversalAccount memory account2 = UniversalAccount({chain: "ETHEREUM", owner: owner2Key});

        // Deploy both UEAs
        address uea1 = factory.deployUEA(account1);
        address uea2 = factory.deployUEA(account2);

        // Verify they have different addresses
        assertTrue(uea1 != uea2);

        // Verify the owner keys are mapped correctly
        (UniversalAccount memory retrievedAccount1, bool isUEA1) = factory.getOriginForUEA(uea1);
        (UniversalAccount memory retrievedAccount2, bool isUEA2) = factory.getOriginForUEA(uea2);
        
        assertEq(keccak256(retrievedAccount1.owner), keccak256(owner1Key));
        assertEq(keccak256(retrievedAccount2.owner), keccak256(owner2Key));
        assertTrue(isUEA1);
        assertTrue(isUEA2);
    }

    // Test for native account detection with empty owner and chain
    function testNativeAccountDetection() public {
        // Create a random address that is not a UEA
        address randomAddr = makeAddr("randomNative");
        
        // Check if it's correctly identified as a native account
        (UniversalAccount memory account, bool isUEA) = factory.getOriginForUEA(randomAddr);
        
        assertFalse(isUEA);
        // For native accounts, both owner and chain should be empty
        assertEq(account.owner.length, 0);
        assertEq(bytes(account.chain).length, 0);
    }
    
    // Test for comparing native and UEA accounts
    function testCompareNativeAndUEAAccounts() public {
        // Create and deploy a UEA
        bytes memory ownerBytes = abi.encodePacked(makeAddr("uea_owner"));
        UniversalAccount memory uea_id = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});
        address ueaAddress = factory.deployUEA(uea_id);
        
        // Create a random native address
        address nativeAddr = makeAddr("native_user");
        
        // Get account info for both
        (UniversalAccount memory ueaAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        (UniversalAccount memory nativeAccount, bool isNativeUEA) = factory.getOriginForUEA(nativeAddr);
        
        // UEA should have proper data and be a UEA
        assertTrue(isUEA);
        assertEq(keccak256(ueaAccount.owner), keccak256(ownerBytes));
        assertEq(keccak256(abi.encode(ueaAccount.chain)), keccak256(abi.encode("ETHEREUM")));
        
        // Native account should be marked as not a UEA and have empty data
        assertFalse(isNativeUEA);
        assertEq(nativeAccount.owner.length, 0);
        assertEq(bytes(nativeAccount.chain).length, 0);
    }
    
    // Test for multiple native accounts all returning empty data
    function testMultipleNativeAccounts() public {
        // Create multiple random addresses
        address[] memory nativeAddrs = new address[](3);
        nativeAddrs[0] = makeAddr("native1");
        nativeAddrs[1] = makeAddr("native2");
        nativeAddrs[2] = makeAddr("native3");
        
        // Check all addresses are correctly identified as native with empty data
        for (uint i = 0; i < nativeAddrs.length; i++) {
            (UniversalAccount memory account, bool isUEA) = factory.getOriginForUEA(nativeAddrs[i]);
            
            assertFalse(isUEA);
            assertEq(account.owner.length, 0);
            assertEq(bytes(account.chain).length, 0);
        }
    }
}
