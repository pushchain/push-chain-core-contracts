// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccountV1.sol";

contract FactoryTest is Test {
    FactoryV1 factory;
    SmartAccountV1 smartAccount;

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerKey;

    address verifierPrecompile;
    SmartAccountV1.OwnerType ownerType;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM;
    SmartAccountV1.OwnerType ownerTypeNonEVM;
    function setUp() public {
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        // Set up user and keys 
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerKey = abi.encodePacked(owner);

        // Set up verifier precompile
        verifierPrecompile = makeAddr("verifierPrecompile");

        // Set up owner type
        ownerType = SmartAccountV1.OwnerType.EVM;
        ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;
        
        ownerKeyNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
    }

    function testImplementationAddress() public {
        assertEq(address(factory.smartAccountImplementation()), address(smartAccount));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public{
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKey,
            ownerType,
            verifierPrecompile
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKey)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(ownerKey)));
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        factory.deploySmartAccount(
            ownerKey,
            ownerType,
            verifierPrecompile
        );

        vm.expectRevert("Account already exists");
        factory.deploySmartAccount(
            ownerKey,
            ownerType,
            verifierPrecompile
        );
    }

    // Test that the computed address matches the deployed address
    function testComputeSmartAccountAddress() public {
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKey,
            ownerType,
            verifierPrecompile
        );

        address computedAddress = factory.computeSmartAccountAddress(ownerKey);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public{
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            ownerTypeNonEVM,
            verifierPrecompile
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKeyNonEVM)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(ownerKeyNonEVM)));
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        factory.deploySmartAccount(
            ownerKeyNonEVM,
            ownerTypeNonEVM,
            verifierPrecompile
        );

        vm.expectRevert("Account already exists");
        factory.deploySmartAccount(
            ownerKeyNonEVM,
            ownerTypeNonEVM,
            verifierPrecompile
        );
    }
    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeSmartAccountAddressNonEVM() public {
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            ownerTypeNonEVM,
            verifierPrecompile
        );

        address computedAddress = factory.computeSmartAccountAddress(ownerKeyNonEVM);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

}