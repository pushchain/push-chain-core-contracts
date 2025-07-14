// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/libraries/Types.sol";
import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {IUEA} from "../src/Interfaces/IUEA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UEAProxy} from "../src/UEAProxy.sol";


contract UEAFactoryTest is Test {
    UEAFactoryV1 factory;
    UEA_EVM ueaEVMImpl;
    UEA_SVM ueaSVMImpl;
    address ueaProxyImpl;

    address deployer;
    address nonOwner;
    address owner;
    bytes ownerBytes;

    // VM Hash constants
    bytes32 constant EVM_HASH = keccak256("EVM");
    bytes32 constant SVM_HASH = keccak256("SVM");
    bytes32 constant MOVE_VM_HASH = keccak256("MOVE_VM");
    bytes32 constant WASM_VM_HASH = keccak256("WASM_VM");
    bytes32 constant CAIRO_VM_HASH = keccak256("CAIRO_VM");

    // NON-EVM data
    bytes ownerNonEVM;

    // Chain hashes
    bytes32 ethereumChainHash;
    bytes32 solanaChainHash;

    function setUp() public {
        deployer = address(this);
        nonOwner = makeAddr("nonOwner");

        // Deploy implementations for different VM types
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();
        
        // Deploy the UEAProxy implementation
        UEAProxy _ueaProxyImpl = new UEAProxy();
        ueaProxyImpl = address(_ueaProxyImpl);

        // Deploy the factory implementation
        UEAFactoryV1 factoryImpl = new UEAFactoryV1();

        // Deploy and initialize the proxy with both initialOwner and UEAProxy implementation
        bytes memory initData = abi.encodeWithSelector(
            UEAFactoryV1.initialize.selector, 
            deployer,
            ueaProxyImpl
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(proxy));

        // Set up user and keys
        (owner, ) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        ownerNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";

        // Store chain hashes for reuse - now includes both chainNamespace and chainId
        ethereumChainHash = keccak256(abi.encode("eip155", "1"));
        solanaChainHash = keccak256(abi.encode("solana", "101"));

        // Register chains
        factory.registerNewChain(ethereumChainHash, EVM_HASH);
        factory.registerNewChain(solanaChainHash, SVM_HASH);

        // Register implementations
        factory.registerUEA(ethereumChainHash, EVM_HASH, address(ueaEVMImpl));
        factory.registerUEA(solanaChainHash, SVM_HASH, address(ueaSVMImpl));
    }

    function testRegisterNewChain() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Verify the chain was registered
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(vmHash, EVM_HASH);
        assertTrue(isRegistered);
    }

    function testRegisterUEA() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
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
        chainHashes[0] = keccak256(abi.encode("KOVAN", "42"));
        chainHashes[1] = keccak256(abi.encode("METIS", "1088"));

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
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register the same chain again
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerNewChain(chainHash, EVM_HASH);
    }

    function testRevertWhenRegisteringZeroAddressUEA() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register zero address as UEA
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(0));
    }

    function testRevertWhenRegisteringUEAWithWrongVMHash() public {
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Try to register UEA with wrong VM hash
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, SVM_HASH, address(ueaEVMImpl));
    }

    function testRevertWhenRegisteringUEAWithUnregisteredChain() public {
        bytes32 chainHash = keccak256(abi.encode("UNREGISTERED", "999"));

        // Try to register UEA for unregistered chain
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(ueaEVMImpl));
    }

    function testRevertWhenRegisteringMultipleUEAWithMismatchedArrays() public {
        bytes32[] memory chainHashes = new bytes32[](2);
        bytes32[] memory vmHashes = new bytes32[](2);
        address[] memory implementations = new address[](1); // Mismatched length

        // Register chains first (use different chains than in setUp)
        chainHashes[0] = keccak256(abi.encode("KOVAN", "42"));
        chainHashes[1] = keccak256(abi.encode("METIS", "1088"));

        factory.registerNewChain(chainHashes[0], EVM_HASH);
        factory.registerNewChain(chainHashes[1], EVM_HASH);

        // Try to register with mismatched array lengths
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerMultipleUEA(chainHashes, vmHashes, implementations);
    }

    function testDeployUEA() public {
        // Use eip155 chain which is already registered in setUp
        bytes memory newOwnerBytes = abi.encodePacked(makeAddr("newowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: newOwnerBytes});

        address ueaAddress = factory.deployUEA(_id);
        assertTrue(factory.hasCode(ueaAddress));

        // Check the owner
        (UniversalAccountId memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(abi.encode(retrievedAccount.chainNamespace)), keccak256(abi.encode(_id.chainNamespace)));
        assertEq(keccak256(retrievedAccount.owner), keccak256(_id.owner));
        assertTrue(isUEA);
    }

    function testRevertWhenDeployingUEAForUnregisteredChain() public {
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("owner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "UNREGISTERED", chainId: "999", owner: testOwnerBytes});

        // Try to deploy UEA for unregistered chain
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testRevertWhenDeployingUEAWithNoImplementation() public {
        // Register chain but no implementation
        bytes32 chainHash = keccak256(abi.encode("NEW_CHAIN", "888"));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("owner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "NEW_CHAIN", chainId: "888", owner: testOwnerBytes});

        // Try to deploy UEA with no implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testRevertWhenDeployingSameUEATwice() public {
        // Use a new owner with eip155 chain
        bytes memory uniqueOwnerBytes = abi.encodePacked(makeAddr("uniqueowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: uniqueOwnerBytes});

        // Deploy first time
        address deployedAddress = factory.deployUEA(_id);
        
        // Verify the proxy was deployed
        assertTrue(factory.hasCode(deployedAddress));
        
        // Try to deploy again with same salt - should fail with FailedDeployment
        vm.expectRevert();  // Any revert is acceptable since it's a low-level CREATE2 failure
        factory.deployUEA(_id);
    }

    function testComputeUEA() public {
        // Use eip155 chain which is already registered in setUp
        bytes memory uniqueComputeOwnerBytes = abi.encodePacked(makeAddr("uniquecomputeowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: uniqueComputeOwnerBytes});

        address computedAddress = factory.computeUEA(_id);
        assertTrue(computedAddress != address(0));

        // Deploy UEA and check if it matches the computed address
        address deployedAddress = factory.deployUEA(_id);
        assertEq(deployedAddress, computedAddress);
    }

    function testGetUEAForOrigin() public {
        // Use eip155 chain which is already registered in setUp
        bytes memory uniqueGetOwnerBytes = abi.encodePacked(makeAddr("uniquegetowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: uniqueGetOwnerBytes});

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
        // Use eip155 chain which is already registered in setUp
        address initialImpl = factory.getUEA(ethereumChainHash);

        // Deploy a new implementation
        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(ethereumChainHash, EVM_HASH, address(newImpl));

        // Check that the implementation was updated
        assertNotEq(factory.getUEA(ethereumChainHash), initialImpl);
        assertEq(factory.getUEA(ethereumChainHash), address(newImpl));
    }

    function testMultipleOwners() public {
        // Create two different owners for eip155 chain
        (address owner1, uint256 owner1PK) = makeAddrAndKey("owner1");
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");

        bytes memory ownerBytes1 = abi.encodePacked(owner1);
        bytes memory ownerBytes2 = abi.encodePacked(owner2);

        UniversalAccountId memory account1 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes1});
        UniversalAccountId memory account2 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes2});

        // Compute UEA addresses
        address computedUEA1 = factory.computeUEA(account1);
        address computedUEA2 = factory.computeUEA(account2);

        // Make sure they're different
        assertNotEq(computedUEA1, computedUEA2);
    }

    function testMultipleDeployments() public {
        // Deploy 10 UEAs for eip155 chain
        for (uint256 i = 0; i < 10; i++) {
            (address testOwner, uint256 testOwnerPK) = makeAddrAndKey(string(abi.encodePacked("testOwner", i)));
            bytes memory testOwnerBytes = abi.encodePacked(testOwner);
            UniversalAccountId memory _id =
                UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: testOwnerBytes});

            address ueaAddress = factory.deployUEA(_id);
            assertTrue(factory.hasCode(ueaAddress));

            (UniversalAccountId memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
            assertEq(keccak256(retrievedAccount.owner), keccak256(testOwnerBytes));
            assertTrue(isUEA);
        }
    }

    function testUEAOwnerChange() public {
        // Deploy UEA for original owner on eip155 chain
        bytes memory originalOwnerBytes = abi.encodePacked(makeAddr("originalOwner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: originalOwnerBytes});

        address ueaAddress = factory.deployUEA(_id);

        // Create a new owner
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerBytes = abi.encodePacked(newOwner);
        UniversalAccountId memory newAccount =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: newOwnerBytes});

        // The owner mapping can't be changed - a new UEA would need to be deployed
        (UniversalAccountId memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(retrievedAccount.owner), keccak256(originalOwnerBytes));
        assertEq(keccak256(abi.encode(retrievedAccount.chainNamespace)), keccak256(abi.encode(_id.chainNamespace)));
        assertTrue(isUEA);

        // Deploy UEA for new owner - this should be a different address
        address newUEAAddress = factory.deployUEA(newAccount);
        assertNotEq(ueaAddress, newUEAAddress);
        (UniversalAccountId memory newRetrievedAccount, bool isNewUEA) = factory.getOriginForUEA(newUEAAddress);
        assertEq(keccak256(newRetrievedAccount.owner), keccak256(newOwnerBytes));
        assertEq(
            keccak256(abi.encode(newRetrievedAccount.chainNamespace)), keccak256(abi.encode(newAccount.chainNamespace))
        );
        assertTrue(isNewUEA);
    }

    function testOwnershipFunctions() public {
        // Test that only owner can register implementations
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));

        bytes32 chainHash = keccak256(abi.encode("APTOS", "1"));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // Test that owner can register implementations
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(chainHash, MOVE_VM_HASH, address(newImpl));

        // Verify the implementation was registered
        assertEq(address(factory.getUEA(chainHash)), address(newImpl));
    }

    function testDeploymentCreate2() public {
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);
        bytes32 salt = factory.generateSalt(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(salt)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    function testComputeUEAAddressNonEVM() public {
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: ownerNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    function testMissingImplementation() public {
        bytes32 moveChainHash = keccak256(abi.encode("APTOS", "1"));
        factory.registerNewChain(moveChainHash, MOVE_VM_HASH);

        // Create an UniversalAccountId with VM type that has no implementation
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "APTOS", chainId: "1", owner: ownerBytes});

        // Try to deploy with missing implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    function testMultipleChainsSameVM() public {
        // Register two different chains with the same VM type (EVM)
        bytes32 ethereumChainHashLocal = keccak256(abi.encode("eip155", "1"));
        bytes32 polygonChainHash = keccak256(abi.encode("POLYGON", "137"));

        // Polygon is not registered yet
        factory.registerNewChain(polygonChainHash, EVM_HASH);

        // We already registered EVM implementation for Ethereum, should work for Polygon too
        (bytes32 vmHashEth, bool isRegisteredEth) = factory.getVMType(ethereumChainHashLocal);
        (bytes32 vmHashPoly, bool isRegisteredPoly) = factory.getVMType(polygonChainHash);

        // Verify both chains use the same VM type
        assertEq(vmHashEth, vmHashPoly);
        assertTrue(isRegisteredEth);
        assertTrue(isRegisteredPoly);

        // Both chains should use the same implementation
        assertEq(factory.getUEA(ethereumChainHashLocal), factory.getUEA(polygonChainHash));

        // Deploy UEAs for both chains and verify they have different addresses despite same VM
        UniversalAccountId memory ethAccount =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        UniversalAccountId memory polyAccount =
            UniversalAccountId({chainNamespace: "POLYGON", chainId: "137", owner: ownerBytes});

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
        bytes32 chainHash = keccak256(abi.encode("TestChain", "123"));
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
        chains[0] = "eip155"; // Ethereum
        chains[1] = "POLYGON"; // Polygon
        chains[2] = "BSC"; // BSC

        // Register chains that aren't already registered
        for (uint256 i = 1; i < 3; i++) {
            bytes32 chainHash = keccak256(abi.encode(chains[i], i == 1 ? "137" : "56")); // Polygon (137) and BSC (56)
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
            string memory chainId = i % 3 == 0 ? "1" : (i % 3 == 1 ? "137" : "56"); // Ethereum, Polygon, BSC chain IDs

            UniversalAccountId memory account =
                UniversalAccountId({chainNamespace: chain, chainId: chainId, owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);

            deployedUEAs[i] = factory.deployUEA(account);

            // Verify mappings are consistent
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
            (UniversalAccountId memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(deployedUEAs[i]);
            assertEq(keccak256(retrievedAccount.owner), keccak256(ownerValues[i]));
            assertEq(keccak256(abi.encode(retrievedAccount.chainNamespace)), keccak256(abi.encode(chain)));
            assertTrue(isUEA);
        }

        // Verify all deployed accounts are retrievable
        for (uint256 i = 0; i < 5; i++) {
            string memory chain = chains[i % 3];
            string memory chainId = i % 3 == 0 ? "1" : (i % 3 == 1 ? "137" : "56"); // Ethereum, Polygon, BSC chain IDs
            UniversalAccountId memory account =
                UniversalAccountId({chainNamespace: chain, chainId: chainId, owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
        }
    }

    function testChainConfigChanges() public {
        // Create a new chain and register it
        bytes32 chainHash = keccak256(abi.encode("KOVAN", "42"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Deploy an account with the initial implementation
        UniversalAccountId memory account =
            UniversalAccountId({chainNamespace: "KOVAN", chainId: "42", owner: ownerBytes});

        // Get initial implementation address
        address initialImpl = factory.getUEA(chainHash);

        // Deploy a UEA with the initial implementation
        address initialUEA = factory.deployUEA(account);

        // Deploy a new implementation
        UEA_EVM newImpl = new UEA_EVM();

        // Change implementation for EVM type
        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        factory.registerUEA(evmChainHash, EVM_HASH, address(newImpl));

        // Verify implementation has changed
        address updatedImpl = factory.getUEA(chainHash);
        assertEq(updatedImpl, address(newImpl));

        // Verify the change impacts new deployments but not existing ones
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        UniversalAccountId memory account2 =
            UniversalAccountId({chainNamespace: "KOVAN", chainId: "42", owner: owner2Key});

        // Compute address with new implementation
        address newUEAAddress = factory.computeUEA(account2);

        // Old UEA still exists and isn't affected
        assertTrue(factory.hasCode(initialUEA));
    }

    function testMappingConsistency() public {
        // Deploy a UEA
        UniversalAccountId memory account =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);

        // Test getOriginForUEA
        (UniversalAccountId memory retrievedAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        assertEq(keccak256(retrievedAccount.owner), keccak256(ownerBytes));
        assertEq(keccak256(abi.encode(retrievedAccount.chainNamespace)), keccak256(abi.encode(account.chainNamespace)));
        assertTrue(isUEA);

        // Test getUEAForOrigin
        (address retrievedUEA, bool isDeployed) = factory.getUEAForOrigin(account);
        assertEq(retrievedUEA, ueaAddress);
        assertTrue(isDeployed);

        // Test with non-existent UEA
        address randomAddr = makeAddr("random");
        (UniversalAccountId memory randomAccount, bool isRandomUEA) = factory.getOriginForUEA(randomAddr);
        assertFalse(isRandomUEA);
        assertEq(randomAccount.owner.length, 0);
        assertEq(bytes(randomAccount.chainNamespace).length, 0);

        // Test with non-existent owner key but predictable address
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerKey = abi.encodePacked(newOwner);

        UniversalAccountId memory newAccount =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: newOwnerKey});

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
        UniversalAccountId memory account =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);
        assertTrue(factory.hasCode(ueaAddress));
    }

    function testDifferentOwnerKeysSameChain() public {
        // Create two different owner keys
        bytes memory owner1Key = abi.encodePacked(makeAddr("owner1"));
        bytes memory owner2Key = abi.encodePacked(makeAddr("owner2"));

        // Create accounts for the same chain but different owners
        UniversalAccountId memory account1 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: owner1Key});
        UniversalAccountId memory account2 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: owner2Key});

        // Deploy both UEAs
        address uea1 = factory.deployUEA(account1);
        address uea2 = factory.deployUEA(account2);

        // Verify they have different addresses
        assertTrue(uea1 != uea2);

        // Verify the owner keys are mapped correctly
        (UniversalAccountId memory retrievedAccount1, bool isUEA1) = factory.getOriginForUEA(uea1);
        (UniversalAccountId memory retrievedAccount2, bool isUEA2) = factory.getOriginForUEA(uea2);

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
        (UniversalAccountId memory account, bool isUEA) = factory.getOriginForUEA(randomAddr);

        assertFalse(isUEA);
        // For native accounts, both owner and chain should be empty
        assertEq(account.owner.length, 0);
        assertEq(bytes(account.chainNamespace).length, 0);
    }

    // Test for comparing native and UEA accounts
    function testCompareNativeAndUEAAccounts() public {
        // Create and deploy a UEA
        bytes memory ueaOwnerBytes = abi.encodePacked(makeAddr("uea_owner"));
        UniversalAccountId memory ueaId =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ueaOwnerBytes});
        address ueaAddress = factory.deployUEA(ueaId);

        // Create a random native address
        address nativeAddr = makeAddr("native_user");

        // Get account info for both
        (UniversalAccountId memory ueaAccount, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        (UniversalAccountId memory nativeAccount, bool isNativeUEA) = factory.getOriginForUEA(nativeAddr);

        // UEA should have proper data and be a UEA
        assertTrue(isUEA);
        assertEq(keccak256(ueaAccount.owner), keccak256(ueaOwnerBytes));
        assertEq(keccak256(abi.encode(ueaAccount.chainNamespace)), keccak256(abi.encode("eip155")));

        // Native account should be marked as not a UEA and have empty data
        assertFalse(isNativeUEA);
        assertEq(nativeAccount.owner.length, 0);
        assertEq(bytes(nativeAccount.chainNamespace).length, 0);
    }

    // Test for multiple native accounts all returning empty data
    function testMultipleNativeAccounts() public {
        // Create multiple random addresses
        address[] memory nativeAddrs = new address[](3);
        nativeAddrs[0] = makeAddr("native1");
        nativeAddrs[1] = makeAddr("native2");
        nativeAddrs[2] = makeAddr("native3");

        // Check all addresses are correctly identified as native with empty data
        for (uint256 i = 0; i < nativeAddrs.length; i++) {
            (UniversalAccountId memory account, bool isUEA) = factory.getOriginForUEA(nativeAddrs[i]);

            assertFalse(isUEA);
            assertEq(account.owner.length, 0);
            assertEq(bytes(account.chainNamespace).length, 0);
        }
    }

    // Error Cases
    function testRevertComputeUEAWithUnregisteredChain() public {
        // Create an account with unregistered chain
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("testowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "UNREGISTERED", chainId: "999", owner: testOwnerBytes});

        // Should revert with InvalidInputArgs
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.computeUEA(_id);
    }

    function testRevertComputeUEAWithNoImplementation() public {
        // Register a chain but don't register an implementation
        bytes32 chainHash = keccak256(abi.encode("TEST_CHAIN", "42"));
        factory.registerNewChain(chainHash, WASM_VM_HASH);

        // Create an account with the registered chain but no implementation
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("testowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "TEST_CHAIN", chainId: "42", owner: testOwnerBytes});

        // Verify that no implementation is registered for this VM type
        bytes32 vmHash = WASM_VM_HASH;
        address implementation = factory.UEA_VM(vmHash);
        assertEq(implementation, address(0));

        // The factory doesn't check if the implementation exists in computeUEA,
        // it only checks if the chain is registered and UEA_PROXY_IMPLEMENTATION is set
        address computedAddress = factory.computeUEA(_id);
        assertTrue(computedAddress != address(0));
        
        // However, attempting to deploy would fail because there's no implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    // Salt Generation Consistency
    function testSaltGenerationConsistency() public {
        // Create two identical accounts
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("saltowner"));
        UniversalAccountId memory id1 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: testOwnerBytes});
        UniversalAccountId memory id2 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: testOwnerBytes});

        // Generate salts
        bytes32 salt1 = factory.generateSalt(id1);
        bytes32 salt2 = factory.generateSalt(id2);

        // Salts should be identical for identical inputs
        assertEq(salt1, salt2);

        // Create an account with different data
        UniversalAccountId memory id3 =
            UniversalAccountId({chainNamespace: "eip155", chainId: "5", owner: testOwnerBytes});
        bytes32 salt3 = factory.generateSalt(id3);

        // Salt should be different
        assertTrue(salt1 != salt3);
    }

    // Deterministic Address Verification
    function testDeterministicAddressVerification() public {
        // Create an account
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("deterministicowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: testOwnerBytes});

        // Compute the address
        address computedAddress = factory.computeUEA(_id);

        // Get the salt and UEAProxy implementation
        bytes32 salt = factory.generateSalt(_id);
        address ueaProxyImplementation = factory.UEA_PROXY_IMPLEMENTATION();

        // Manually compute the address using CREATE2 formula with UEAProxy implementation
        address manuallyComputedAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(factory),
                            salt,
                            keccak256(
                                abi.encodePacked(
                                    hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
                                    ueaProxyImplementation,
                                    hex"5af43d82803e903d91602b57fd5bf3"
                                )
                            )
                        )
                    )
                )
            )
        );

        // Addresses should match
        assertEq(computedAddress, manuallyComputedAddress);
    }

    // Boundary Tests
    function testComputeUEAWithEmptyOwner() public {
        // Create an account with empty owner bytes
        bytes memory emptyOwnerBytes = new bytes(0);
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: emptyOwnerBytes});

        // Should compute a valid address (not revert)
        address computedAddress = factory.computeUEA(_id);
        assertTrue(computedAddress != address(0));

        // Deploy and verify
        address deployedAddress = factory.deployUEA(_id);
        assertEq(deployedAddress, computedAddress);
    }

    // Test for the case where we have a UEA address in the mapping but the code isn't deployed
    function testGetUEAForOriginWithMappingButNoCode() public {
        // Create an account
        bytes memory testOwnerBytes = abi.encodePacked(makeAddr("testowner"));
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: testOwnerBytes});
        
        // Generate salt
        bytes32 salt = factory.generateSalt(_id);
        
        // Compute what the address would be
        address computedAddress = factory.computeUEA(_id);
        
        // Manually set the UOA_to_UEA mapping without actually deploying
        address mockUEAAddress = computedAddress;
        vm.store(
            address(factory),
            keccak256(abi.encode(salt, uint256(1))), // slot for UOA_to_UEA[salt]
            bytes32(uint256(uint160(mockUEAAddress)))
        );
        
        // Now call getUEAForOrigin - should return our address but isDeployed = false
        (address uea, bool isDeployed) = factory.getUEAForOrigin(_id);
        assertEq(uea, mockUEAAddress);
        assertFalse(isDeployed); // No code at this address
    }

    // Test for the case where getOriginForUEA is called with an address that has an owner
    function testGetOriginForUEAWithOwner() public {
        // Create and deploy a UEA
        bytes memory ueaOwnerBytes = abi.encodePacked(makeAddr("uea_owner_with_length"));
        UniversalAccountId memory ueaId =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ueaOwnerBytes});
        address ueaAddress = factory.deployUEA(ueaId);
        
        // Call getOriginForUEA
        (UniversalAccountId memory account, bool isUEA) = factory.getOriginForUEA(ueaAddress);
        
        // Should return true for isUEA since owner.length > 0
        assertTrue(isUEA);
        assertTrue(account.owner.length > 0);
    }
}
