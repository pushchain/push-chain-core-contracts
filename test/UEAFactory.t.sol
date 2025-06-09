// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {UniversalAccount} from "../src/libraries/Types.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract UEAFactoryTest is Test {
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

    function setUp() public {
        deployer = address(this);
        nonOwner = makeAddr("nonOwner");

        // Deploy implementations for different VM types
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();

        // Deploy factory
        factory = new UEAFactoryV1();

        // Set up user and keys
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        // Set up verifier precompile
        verifierPrecompile = 0x0000000000000000000000000000000000000902;

        ownerNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
        solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

        // Register chains
        bytes32 evmChainHash = keccak256(abi.encode("ETHEREUM"));
        factory.registerNewChain(evmChainHash, EVM_HASH);

        bytes32 svmChainHash = keccak256(abi.encode("SOLANA"));
        factory.registerNewChain(svmChainHash, SVM_HASH);

        // Register implementations
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));
        factory.registerUEA(svmChainHash, SVM_HASH, address(ueaSVMImpl));
    }

    function testOwnershipFunctions() public {
        // Test that only owner can register implementations
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));

        bytes32 chainHash = keccak256(abi.encode("APTOS"));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // Test that owner can register implementations
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(chainHash, MOVE_VM_HASH, address(newImpl));

        // Verify the implementation was registered
        assertEq(address(factory.getUEA(chainHash)), address(newImpl));
    }

    function testRegisterMultipleUEA() public {
        // Create new implementations
        UEA_EVM impl1 = new UEA_EVM();
        UEA_SVM impl2 = new UEA_SVM();

        // Create arrays for registration
        bytes32[] memory chainHashes = new bytes32[](2);
        chainHashes[0] = keccak256(abi.encode("NEAR"));
        chainHashes[1] = keccak256(abi.encode("STARKNET"));

        // Register chains
        factory.registerNewChain(chainHashes[0], WASM_VM_HASH);
        factory.registerNewChain(chainHashes[1], CAIRO_VM_HASH);

        bytes32[] memory vmHashes = new bytes32[](2);
        vmHashes[0] = WASM_VM_HASH;
        vmHashes[1] = CAIRO_VM_HASH;

        address[] memory implementations = new address[](2);
        implementations[0] = address(impl1);
        implementations[1] = address(impl2);

        // Register multiple implementations
        factory.registerMultipleUEA(chainHashes, vmHashes, implementations);

        // Verify implementations were registered
        assertEq(address(factory.getUEA(chainHashes[0])), address(impl1));
        assertEq(address(factory.getUEA(chainHashes[1])), address(impl2));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);
        bytes32 salt = factory.generateSalt(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(salt)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address
    function testComputeUEAAddress() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "SOLANA", owner: ownerNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        bytes32 salt = factory.generateSalt(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(salt)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "SOLANA", owner: ownerNonEVM});

        address ueaAddress = factory.deployUEA(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeUEAAddressNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "SOLANA", owner: ownerNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    // Test missing implementation for a VM type
    function testMissingImplementation() public {
        bytes32 moveChainHash = keccak256(abi.encode("APTOS"));
        factory.registerNewChain(moveChainHash, MOVE_VM_HASH);

        // Create an UniversalAccount with VM type that has no implementation
        UniversalAccount memory _id = UniversalAccount({CHAIN: "APTOS", owner: ownerBytes});

        // Try to deploy with missing implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.deployUEA(_id);
    }

    // Test Multiple Chain Types with Same VM
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
        UniversalAccount memory ethAccount = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        UniversalAccount memory polyAccount = UniversalAccount({CHAIN: "POLYGON", owner: ownerBytes});

        address ethUEA = factory.deployUEA(ethAccount);

        // Need a different owner key for the second account since same owner key can't be used twice
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        polyAccount.owner = owner2Key;
        address polyUEA = factory.deployUEA(polyAccount);

        // Addresses should be different despite same VM type
        assertTrue(ethUEA != polyUEA);
    }

    // Test Ownership Transfer
    function testOwnershipTransfer() public {
        address newOwner = makeAddr("newOwner");

        // Transfer ownership to new owner
        factory.transferOwnership(newOwner);

        // Verify new owner
        assertEq(factory.owner(), newOwner);

        // Try to register a chain with old owner, should fail
        bytes32 chainHash = keccak256(abi.encode("TestChain"));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // New owner should be able to register a chain
        vm.prank(newOwner);
        factory.registerNewChain(chainHash, MOVE_VM_HASH);

        // Verify chain is registered
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(vmHash, MOVE_VM_HASH);
        assertTrue(isRegistered);
    }

    // Test Factory Lifecycle
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

            UniversalAccount memory account = UniversalAccount({CHAIN: chain, owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);
            
            deployedUEAs[i] = factory.deployUEA(account);

            // Verify mappings are consistent
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
            assertEq(factory.getOwnerForUEA(deployedUEAs[i]), ownerValues[i]);
        }

        // Verify all deployed accounts are retrievable
        for (uint256 i = 0; i < 5; i++) {
            UniversalAccount memory account = UniversalAccount({CHAIN: chains[i % 3], owner: ownerValues[i]});
            bytes32 salt = factory.generateSalt(account);
            assertEq(factory.UOA_to_UEA(salt), deployedUEAs[i]);
        }
    }

    // Test Chain Configuration Changes
    function testChainConfigChanges() public {
        // Create a new chain and register it
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Deploy an account with the initial implementation
        UniversalAccount memory account = UniversalAccount({CHAIN: "KOVAN", owner: ownerBytes});

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

        UniversalAccount memory account2 = UniversalAccount({CHAIN: "KOVAN", owner: owner2Key});

        // Compute address with new implementation
        address newUEAAddress = factory.computeUEA(account2);

        // Old UEA still exists and isn't affected
        assertTrue(factory.hasCode(initialUEA));
    }

    // Test Address Prediction Accuracy
    function testAddressPredictionAccuracy() public {
        // Create a range of different keys
        for (uint256 i = 1; i <= 5; i++) {
            (address testOwner, uint256 testOwnerPK) = makeAddrAndKey(string(abi.encodePacked("testOwner", i)));
            bytes memory testOwnerKey = abi.encodePacked(testOwner);

            UniversalAccount memory account = UniversalAccount({CHAIN: "ETHEREUM", owner: testOwnerKey});

            // Predict address before deployment
            address predictedAddress = factory.computeUEA(account);

            // Deploy UEA
            address deployedAddress = factory.deployUEA(account);

            // Verify prediction matches deployment
            assertEq(predictedAddress, deployedAddress);
        }
    }

    // Test Mapping Consistency
    function testMappingConsistency() public {
        // Deploy a UEA
        UniversalAccount memory account = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);

        // Test getOwnerForUEA
        bytes memory retrievedOwner = factory.getOwnerForUEA(ueaAddress);
        assertEq(keccak256(retrievedOwner), keccak256(ownerBytes));

        // Test getUEAForOwner
        (address retrievedUEA, bool isDeployed) = factory.getUEAForOwner(account);
        assertEq(retrievedUEA, ueaAddress);
        assertTrue(isDeployed);

        // Test with non-existent UEA
        address randomAddr = makeAddr("random");
        bytes memory emptyOwner = factory.getOwnerForUEA(randomAddr);
        assertEq(emptyOwner.length, 0);

        // Test with non-existent owner key but predictable address
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerKey = abi.encodePacked(newOwner);

        UniversalAccount memory newAccount = UniversalAccount({CHAIN: "ETHEREUM", owner: newOwnerKey});

        // Compute without deploying
        address computedAddress = factory.computeUEA(newAccount);

        // Verify getUEAForOwner returns computed address but shows not deployed
        (address predictedAddress, bool isNewDeployed) = factory.getUEAForOwner(newAccount);
        assertEq(predictedAddress, computedAddress);
        assertFalse(isNewDeployed);
    }

    // Test Factory State Verification
    function testFactoryStateVerification() public {
        // Register a new chain and implementation
        bytes32 chainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(chainHash, EVM_HASH);

        // Verify chain registration state
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(vmHash, EVM_HASH);
        assertTrue(isRegistered);

        // Verify implementation mapping
        address impl = factory.getUEA(chainHash);
        assertEq(impl, address(ueaEVMImpl));

        // Verify VM type mapping
        assertEq(factory.CHAIN_to_VM(chainHash), EVM_HASH);

        // Verify salt generation is deterministic
        UniversalAccount memory account = UniversalAccount({CHAIN: "KOVAN", owner: ownerBytes});

        bytes32 salt1 = factory.generateSalt(account);
        bytes32 salt2 = factory.generateSalt(account);
        assertEq(salt1, salt2);

        // Verify different accounts produce different salts
        (address otherOwner,) = makeAddrAndKey("otherOwner");
        bytes memory otherOwnerKey = abi.encodePacked(otherOwner);

        UniversalAccount memory otherAccount = UniversalAccount({CHAIN: "KOVAN", owner: otherOwnerKey});

        bytes32 otherSalt = factory.generateSalt(otherAccount);
        assertTrue(salt1 != otherSalt);
    }

    // Test non-zero address has code detection
    function testHasCode() public {
        // Contract address should have code
        assertTrue(factory.hasCode(address(factory)));

        // EOA should not have code
        assertFalse(factory.hasCode(address(0x123)));

        // Newly deployed UEA should have code
        UniversalAccount memory account = UniversalAccount({CHAIN: "ETHEREUM", owner: ownerBytes});

        address ueaAddress = factory.deployUEA(account);
        assertTrue(factory.hasCode(ueaAddress));
    }

    // Test registering UEA with mismatched vmHash
    function testRegisterUEAWithMismatchedVMHash() public {
        // Create a new chain with EVM_HASH
        bytes32 chainHash = keccak256(abi.encode("ARBITRUM"));
        factory.registerNewChain(chainHash, EVM_HASH);
        
        // Try to register UEA with mismatched vmHash (SVM_HASH instead of EVM_HASH)
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, SVM_HASH, address(ueaEVMImpl));
    }
    
    // Test trying to register the same chain twice
    function testRegisterSameChainTwice() public {
        // Try to register Ethereum chain again (already registered in setUp)
        bytes32 chainHash = keccak256(abi.encode("ETHEREUM"));
        
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerNewChain(chainHash, EVM_HASH);
    }
    
    // Test handling different owner keys with the same chain
    function testDifferentOwnerKeysSameChain() public {
        // Create two different owner keys
        bytes memory owner1Key = abi.encodePacked(makeAddr("owner1"));
        bytes memory owner2Key = abi.encodePacked(makeAddr("owner2"));
        
        // Create accounts for the same chain but different owners
        UniversalAccount memory account1 = UniversalAccount({CHAIN: "ETHEREUM", owner: owner1Key});
        UniversalAccount memory account2 = UniversalAccount({CHAIN: "ETHEREUM", owner: owner2Key});
        
        // Deploy both UEAs
        address uea1 = factory.deployUEA(account1);
        address uea2 = factory.deployUEA(account2);
        
        // Verify they have different addresses
        assertTrue(uea1 != uea2);
        
        // Verify the owner keys are mapped correctly
        assertEq(keccak256(factory.getOwnerForUEA(uea1)), keccak256(owner1Key));
        assertEq(keccak256(factory.getOwnerForUEA(uea2)), keccak256(owner2Key));
    }
    
    // Test using an unregistered VM hash with registerUEA
    function testUnregisteredVMHashInRegisterUEA() public {
        // Create a fake VM hash that doesn't exist
        bytes32 fakeVMHash = keccak256("FAKE_VM");
        bytes32 chainHash = keccak256(abi.encode("FANTOM"));
        
        // Register the chain with EVM hash
        factory.registerNewChain(chainHash, EVM_HASH);
        
        // Try to register UEA with unregistered VM hash
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, fakeVMHash, address(ueaEVMImpl));
    }
    
    // Test registering implementation for unregistered chain
    function testRegisterImplForUnregisteredChain() public {
        // Chain hash for unregistered chain
        bytes32 chainHash = keccak256(abi.encode("UNREGISTERED_CHAIN"));
        
        // Try to register implementation for unregistered chain
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(ueaEVMImpl));
    }
    
    // Test re-registering an implementation for a VM type
    function testReRegisterImplementation() public {
        // Create new implementation
        UEA_EVM newImpl = new UEA_EVM();
        
        // Get Ethereum chain hash
        bytes32 chainHash = keccak256(abi.encode("ETHEREUM"));
        
        // Register new implementation, should override old one
        factory.registerUEA(chainHash, EVM_HASH, address(newImpl));
        
        // Verify implementation was updated
        assertEq(factory.getUEA(chainHash), address(newImpl));
        
        // Make sure it's also updated for all chains using EVM
        bytes32 kovanChainHash = keccak256(abi.encode("KOVAN"));
        factory.registerNewChain(kovanChainHash, EVM_HASH);
        
        // Kovan should also use the new implementation
        assertEq(factory.getUEA(kovanChainHash), address(newImpl));
    }
    
    // Test invalid array lengths in registerMultipleUEA
    function testInvalidArrayLengthsInRegisterMultipleUEA() public {
        // Create arrays with different lengths
        bytes32[] memory chainHashes = new bytes32[](2);
        chainHashes[0] = keccak256(abi.encode("AVALANCHE"));
        chainHashes[1] = keccak256(abi.encode("FANTOM"));
        
        bytes32[] memory vmHashes = new bytes32[](2);
        vmHashes[0] = EVM_HASH;
        vmHashes[1] = EVM_HASH;
        
        // Register the chains
        factory.registerNewChain(chainHashes[0], vmHashes[0]);
        factory.registerNewChain(chainHashes[1], vmHashes[1]);
        
        // Create array of implementations with different length
        address[] memory implementations = new address[](1);
        implementations[0] = address(ueaEVMImpl);
        
        // Should revert due to length mismatch
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerMultipleUEA(chainHashes, vmHashes, implementations);
    }
    
    // Test empty implementation address in registerUEA
    function testEmptyImplAddressInRegisterUEA() public {
        // Register a new chain
        bytes32 chainHash = keccak256(abi.encode("CELO"));
        factory.registerNewChain(chainHash, EVM_HASH);
        
        // Try to register with zero address implementation
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        factory.registerUEA(chainHash, EVM_HASH, address(0));
    }
}
