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
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: "eip155:1",
            ownerKey: ownerKey
        });
        
        address ueaAddress = factory.deployUEA(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(ownerKey)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: "eip155:1",
            ownerKey: ownerKey
        });
        
        address ueaAddress = factory.deployUEA(_id);
        
        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address
    function testComputeUEAAddress() public {
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: "eip155:1",
            ownerKey: ownerKey
        });
        
        address ueaAddress = factory.deployUEA(_id);
        address computedAddress = factory.computeUEA(_id);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", ueaAddress);

        assertEq(ueaAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public {
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: solanaChainId,
            ownerKey: ownerKeyNonEVM
        });
        
        address ueaAddress = factory.deployUEA(_id);
        assertEq(ueaAddress, address(factory.UOA_to_UEA(ownerKeyNonEVM)));
        assertEq(ueaAddress, address(factory.computeUEA(_id)));
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: solanaChainId,
            ownerKey: ownerKeyNonEVM
        });
        
        address ueaAddress = factory.deployUEA(_id);

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        factory.deployUEA(_id);
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeUEAAddressNonEVM() public {
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: solanaChainId,
            ownerKey: ownerKeyNonEVM
        });
        
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
        UniversalAccount memory _id = UniversalAccount({
            CHAIN: "MOVE_VM:APTOS",
            ownerKey: ownerKey
        });

        // Try to deploy with missing implementation
        vm.expectRevert("No _ueaImplementation for this VM type");
        factory.deployUEA(_id);
    }
}
