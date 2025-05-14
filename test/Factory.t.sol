// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountV1} from "../src/smartAccounts/SmartAccountV1.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {AccountId, VM_TYPE} from "../src/libraries/Types.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FactoryTest is Test {
    FactoryV1 factory;
    SmartAccountV1 smartAccountEVM;
    SmartAccountV1 smartAccountSVM;

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
        smartAccountEVM = new SmartAccountV1();
        smartAccountSVM = new SmartAccountV1();

        // Create arrays for constructor
        address[] memory implementations = new address[](2);
        implementations[0] = address(smartAccountEVM);
        implementations[1] = address(smartAccountSVM);

        uint256[] memory vmTypes = new uint256[](2);
        vmTypes[0] = uint256(VM_TYPE.EVM);
        vmTypes[1] = uint256(VM_TYPE.SVM);

        // Deploy factory with multiple implementations
        factory = new FactoryV1(implementations, vmTypes);

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
    }

    function testImplementationAddress() public view {
        assertEq(address(factory.getImplementation(VM_TYPE.EVM)), address(smartAccountEVM));

        assertEq(address(factory.getImplementation(VM_TYPE.SVM)), address(smartAccountSVM));
    }

    function testConstructorValidation() public {
        // Test with mismatched array lengths
        address[] memory implementations = new address[](2);
        implementations[0] = address(smartAccountEVM);
        implementations[1] = address(smartAccountSVM);

        uint256[] memory vmTypes = new uint256[](1);
        vmTypes[0] = uint256(VM_TYPE.EVM);

        vm.expectRevert(Errors.InvalidInputArgs.selector);
        new FactoryV1(implementations, vmTypes);
    }

    function testOwnershipFunctions() public {
        // Test that only owner can register implementations
        vm.prank(nonOwner);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        factory.registerImplementation(uint256(VM_TYPE.MOVE_VM), address(0x123));

        // Test that owner can register implementations
        SmartAccountV1 newImpl = new SmartAccountV1();
        factory.registerImplementation(uint256(VM_TYPE.MOVE_VM), address(newImpl));

        // Verify the implementation was registered
        assertEq(address(factory.getImplementation(VM_TYPE.MOVE_VM)), address(newImpl));
    }

    function testRegisterMultipleImplementations() public {
        // Create new implementations
        SmartAccountV1 impl1 = new SmartAccountV1();
        SmartAccountV1 impl2 = new SmartAccountV1();

        // Create arrays for registration
        address[] memory implementations = new address[](2);
        implementations[0] = address(impl1);
        implementations[1] = address(impl2);

        uint256[] memory vmTypes = new uint256[](2);
        vmTypes[0] = uint256(VM_TYPE.WASM_VM);
        vmTypes[1] = uint256(VM_TYPE.CAIRO_VM);

        // Register multiple implementations
        factory.registerMultipleImplementations(vmTypes, implementations);

        // Verify implementations were registered
        assertEq(address(factory.getImplementation(VM_TYPE.WASM_VM)), address(impl1));

        assertEq(address(factory.getImplementation(VM_TYPE.CAIRO_VM)), address(impl2));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public {
        AccountId memory _id = AccountId({namespace: "eip155", chainId: "1", ownerKey: ownerKey, vmType: vmType});
        address smartAccountAddress = factory.deploySmartAccount(_id);
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKey)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(_id)));
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        AccountId memory _id = AccountId({namespace: "eip155", chainId: "1", ownerKey: ownerKey, vmType: vmType});
        address smartAccountAddress = factory.deploySmartAccount(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deploySmartAccount(_id);
    }

    // Test that the computed address matches the deployed address
    function testComputeSmartAccountAddress() public {
        AccountId memory _id = AccountId({namespace: "eip155", chainId: "1", ownerKey: ownerKey, vmType: vmType});
        address smartAccountAddress = factory.deploySmartAccount(_id);

        address computedAddress = factory.computeSmartAccountAddress(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public {
        AccountId memory _id = AccountId({
            namespace: "solana",
            chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            ownerKey: ownerKeyNonEVM,
            vmType: vmTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKeyNonEVM)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(_id)));
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        AccountId memory _id = AccountId({
            namespace: "solana",
            chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            ownerKey: ownerKeyNonEVM,
            vmType: vmTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deploySmartAccount(_id);
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeSmartAccountAddressNonEVM() public {
        AccountId memory _id = AccountId({
            namespace: "solana",
            chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            ownerKey: ownerKeyNonEVM,
            vmType: vmTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        address computedAddress = factory.computeSmartAccountAddress(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

    // Test missing implementation for a VM type
    function testMissingImplementation() public {
        // Create an AccountId with VM type that has no implementation
        AccountId memory _id = AccountId({
            namespace: "eip155",
            chainId: "1",
            ownerKey: ownerKey,
            vmType: VM_TYPE.MOVE_VM // No implementation registered for this yet
        });

        // Try to deploy with missing implementation
        vm.expectRevert("No implementation for this VM type");
        factory.deploySmartAccount(_id);
    }
}
