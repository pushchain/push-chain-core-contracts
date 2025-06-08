// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {UniversalAccount, VM_TYPE} from "../src/libraries/Types.sol";
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
    bytes ownerKey;

    address verifierPrecompile;
    VM_TYPE vmType;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM;
    VM_TYPE vmTypeNonEVM;
    string solanaChainId;
    string solanaAddress;

    function setUp() public {
        deployer = address(this);
        nonOwner = makeAddr("nonOwner");

        // Deploy implementations for different VM types
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();

        // Create arrays for constructor
        address[] memory implementations = new address[](2);
        implementations[0] = address(ueaEVMImpl);
        implementations[1] = address(ueaSVMImpl);

        uint256[] memory vmTypes = new uint256[](2);
        vmTypes[0] = uint256(VM_TYPE.EVM);
        vmTypes[1] = uint256(VM_TYPE.SVM);

        // Deploy factory
        factory = new UEAFactoryV1();

        // Set up user and keys
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerKey = abi.encodePacked(owner);

        // Set up verifier precompile
        verifierPrecompile = 0x0000000000000000000000000000000000000902;

        // Set up owner type
        vmType = VM_TYPE.EVM;
        vmTypeNonEVM = VM_TYPE.SVM;

        ownerKeyNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
        solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

        // Register chains
        bytes32 evmChainHash = keccak256(abi.encode("eip155:1"));
        factory.registerNewChain(evmChainHash, VM_TYPE.EVM);

        bytes32 svmChainHash = keccak256(abi.encode(solanaChainId));
        factory.registerNewChain(svmChainHash, VM_TYPE.SVM);

        // Register implementations
        factory.registerUEA(evmChainHash, address(ueaEVMImpl));
        factory.registerUEA(svmChainHash, address(ueaSVMImpl));
    }

    function testOwnershipFunctions() public {
        // Test that only owner can register implementations
        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));

        bytes32 chainHash = keccak256(abi.encode("MOVE_VM:APTOS"));
        factory.registerNewChain(chainHash, VM_TYPE.MOVE_VM);

        // Test that owner can register implementations
        factory.registerNewChain(chainHash, VM_TYPE.MOVE_VM);

        UEA_EVM newImpl = new UEA_EVM();
        factory.registerUEA(chainHash, address(newImpl));

        // Verify the implementation was registered
        assertEq(address(factory.getUEA(chainHash)), address(newImpl));
    }

    function testRegisterMultipleUEA() public {
        // Create new implementations
        UEA_EVM impl1 = new UEA_EVM();
        UEA_SVM impl2 = new UEA_SVM();

        // Create arrays for registration
        bytes32[] memory chainHashes = new bytes32[](2);
        chainHashes[0] = keccak256(abi.encode("WASM_VM:NEAR"));
        chainHashes[1] = keccak256(abi.encode("CAIRO_VM:STARKNET"));

        // Register chains
        factory.registerNewChain(chainHashes[0], VM_TYPE.WASM_VM);
        factory.registerNewChain(chainHashes[1], VM_TYPE.CAIRO_VM);

        address[] memory implementations = new address[](2);
        implementations[0] = address(impl1);
        implementations[1] = address(impl2);

        // Register multiple implementations
        factory.registerMultipleUEA(chainHashes, implementations);

        // Verify implementations were registered
        assertEq(address(factory.getUEA(chainHashes[0])), address(impl1));
        assertEq(address(factory.getUEA(chainHashes[1])), address(impl2));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        address ueaAddress = factory.deployUEA(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(ownerKey)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        address ueaAddress = factory.deployUEA(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address
    function testComputeUEAAddress() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: solanaChainId, ownerKey: ownerKeyNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(ownerKeyNonEVM)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: solanaChainId, ownerKey: ownerKeyNonEVM});

        address ueaAddress = factory.deployUEA(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeUEAAddressNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({CHAIN: solanaChainId, ownerKey: ownerKeyNonEVM});

        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    // Test missing implementation for a VM type
    function testMissingImplementation() public {
        bytes32 moveChainHash = keccak256(abi.encode("MOVE_VM:APTOS"));
        factory.registerNewChain(moveChainHash, VM_TYPE.MOVE_VM);

        // Create an UniversalAccount with VM type that has no implementation
        UniversalAccount memory _id = UniversalAccount({CHAIN: "MOVE_VM:APTOS", ownerKey: ownerKey});

        // Try to deploy with missing implementation
        vm.expectRevert("No _ueaImplementation for this VM type");
        factory.deployUEA(_id);
    }

    // Test Multiple Chain Types with Same VM
    function testMultipleChainsSameVM() public {
        // Register two different chains with the same VM type (EVM)
        bytes32 ethereumChainHash = keccak256(abi.encode("eip155:1"));
        bytes32 polygonChainHash = keccak256(abi.encode("eip155:137"));

        // Polygon is not registered yet
        factory.registerNewChain(polygonChainHash, VM_TYPE.EVM);

        // We already registered EVM implementation for Ethereum, should work for Polygon too
        (VM_TYPE vmTypeEth, bool isRegisteredEth) = factory.getVMType(ethereumChainHash);
        (VM_TYPE vmTypePoly, bool isRegisteredPoly) = factory.getVMType(polygonChainHash);

        // Verify both chains use the same VM type
        assertEq(uint256(vmTypeEth), uint256(vmTypePoly));
        assertTrue(isRegisteredEth);
        assertTrue(isRegisteredPoly);

        // Both chains should use the same implementation
        assertEq(factory.getUEA(ethereumChainHash), factory.getUEA(polygonChainHash));

        // Deploy UEAs for both chains and verify they have different addresses despite same VM
        UniversalAccount memory ethAccount = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        UniversalAccount memory polyAccount = UniversalAccount({CHAIN: "eip155:137", ownerKey: ownerKey});

        address ethUEA = factory.deployUEA(ethAccount);

        // Need a different owner key for the second account since same owner key can't be used twice
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        polyAccount.ownerKey = owner2Key;
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
        factory.registerNewChain(chainHash, VM_TYPE.MOVE_VM);

        // New owner should be able to register a chain
        vm.prank(newOwner);
        factory.registerNewChain(chainHash, VM_TYPE.MOVE_VM);

        // Verify chain is registered
        (VM_TYPE vmType, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(uint256(vmType), uint256(VM_TYPE.MOVE_VM));
        assertTrue(isRegistered);
    }

    // Test Factory Lifecycle
    function testFactoryLifecycle() public {
        // Create multiple owners
        address[] memory owners = new address[](5);
        bytes[] memory ownerKeys = new bytes[](5);

        for (uint256 i = 0; i < 5; i++) {
            (owners[i],) = makeAddrAndKey(string(abi.encodePacked("owner", i)));
            ownerKeys[i] = abi.encodePacked(owners[i]);
        }

        // Register multiple chains
        string[] memory chains = new string[](3);
        chains[0] = "eip155:1"; // Ethereum
        chains[1] = "eip155:137"; // Polygon
        chains[2] = "eip155:56"; // BSC

        // Register chains that aren't already registered
        for (uint256 i = 1; i < 3; i++) {
            bytes32 chainHash = keccak256(abi.encode(chains[i]));
            // Check if chain is already registered
            (, bool isRegistered) = factory.getVMType(chainHash);
            if (!isRegistered) {
                factory.registerNewChain(chainHash, VM_TYPE.EVM);
            }
        }

        // Deploy accounts for different combinations
        address[] memory deployedUEAs = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            string memory chain = chains[i % 3]; // Cycle through chains

            UniversalAccount memory account = UniversalAccount({CHAIN: chain, ownerKey: ownerKeys[i]});

            deployedUEAs[i] = factory.deployUEA(account);

            // Verify mappings are consistent
            assertEq(factory.UOA_to_UEA(ownerKeys[i]), deployedUEAs[i]);
            assertEq(factory.getOwnerForUEA(deployedUEAs[i]), ownerKeys[i]);
        }

        // Verify all deployed accounts are retrievable
        for (uint256 i = 0; i < 5; i++) {
            assertEq(factory.UOA_to_UEA(ownerKeys[i]), deployedUEAs[i]);
        }
    }

    // Test Chain Configuration Changes
    function testChainConfigChanges() public {
        // Create a new chain and register it
        bytes32 chainHash = keccak256(abi.encode("eip155:42")); // Kovan
        factory.registerNewChain(chainHash, VM_TYPE.EVM);

        // Deploy an account with the initial implementation
        UniversalAccount memory account = UniversalAccount({CHAIN: "eip155:42", ownerKey: ownerKey});

        // Get initial implementation address
        address initialImpl = factory.getUEA(chainHash);

        // Deploy a UEA with the initial implementation
        address initialUEA = factory.deployUEA(account);

        // Deploy a new implementation
        UEA_EVM newImpl = new UEA_EVM();

        // Change implementation for EVM type
        bytes32 evmChainHash = keccak256(abi.encode("eip155:1"));
        factory.registerUEA(evmChainHash, address(newImpl));

        // Verify implementation has changed
        address updatedImpl = factory.getUEA(chainHash);
        assertEq(updatedImpl, address(newImpl));

        // Verify the change impacts new deployments but not existing ones
        (address owner2, uint256 owner2PK) = makeAddrAndKey("owner2");
        bytes memory owner2Key = abi.encodePacked(owner2);

        UniversalAccount memory account2 = UniversalAccount({CHAIN: "eip155:42", ownerKey: owner2Key});

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

            UniversalAccount memory account = UniversalAccount({CHAIN: "eip155:1", ownerKey: testOwnerKey});

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
        UniversalAccount memory account = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        address ueaAddress = factory.deployUEA(account);

        // Test getOwnerForUEA
        bytes memory retrievedOwnerKey = factory.getOwnerForUEA(ueaAddress);
        assertEq(keccak256(retrievedOwnerKey), keccak256(ownerKey));

        // Test getUEAForOwner
        (address retrievedUEA, bool isDeployed) = factory.getUEAForOwner(account);
        assertEq(retrievedUEA, ueaAddress);
        assertTrue(isDeployed);

        // Test with non-existent UEA
        address randomAddr = makeAddr("random");
        bytes memory emptyOwnerKey = factory.getOwnerForUEA(randomAddr);
        assertEq(emptyOwnerKey.length, 0);

        // Test with non-existent owner key but predictable address
        (address newOwner, uint256 newOwnerPK) = makeAddrAndKey("newOwner");
        bytes memory newOwnerKey = abi.encodePacked(newOwner);

        UniversalAccount memory newAccount = UniversalAccount({CHAIN: "eip155:1", ownerKey: newOwnerKey});

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
        bytes32 chainHash = keccak256(abi.encode("eip155:42"));
        factory.registerNewChain(chainHash, VM_TYPE.EVM);

        // Verify chain registration state
        (VM_TYPE vmType, bool isRegistered) = factory.getVMType(chainHash);
        assertEq(uint256(vmType), uint256(VM_TYPE.EVM));
        assertTrue(isRegistered);

        // Verify implementation mapping
        address impl = factory.getUEA(chainHash);
        assertEq(impl, address(ueaEVMImpl));

        // Verify VM type mapping
        assertEq(uint256(factory.CHAIN_to_VM(chainHash)), uint256(VM_TYPE.EVM));

        // Verify salt generation is deterministic
        UniversalAccount memory account = UniversalAccount({CHAIN: "eip155:42", ownerKey: ownerKey});

        bytes32 salt1 = factory.generateSalt(account);
        bytes32 salt2 = factory.generateSalt(account);
        assertEq(salt1, salt2);

        // Verify different accounts produce different salts
        (address otherOwner,) = makeAddrAndKey("otherOwner");
        bytes memory otherOwnerKey = abi.encodePacked(otherOwner);

        UniversalAccount memory otherAccount = UniversalAccount({CHAIN: "eip155:42", ownerKey: otherOwnerKey});

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
        UniversalAccount memory account = UniversalAccount({CHAIN: "eip155:1", ownerKey: ownerKey});

        address ueaAddress = factory.deployUEA(account);
        assertTrue(factory.hasCode(ueaAddress));
    }
}
