// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {CAIP10} from "./utils/caip.sol";

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
    string solanaChainId;
    string solanaAddress;

    function setUp() public {
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        // Set up user and keys
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerKey = abi.encodePacked(owner);

        // Set up verifier precompile
     address verifierPrecompile = 0x0000000000000000000000000000000000000902;

        // Set up owner type
        ownerType = SmartAccountV1.OwnerType.EVM;
        ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;

        ownerKeyNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
        solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";
    }

    function testImplementationAddress() public view {
        assertEq(
            address(factory.smartAccountImplementation()),
            address(smartAccount)
        );
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public {
        string memory caip = CAIP10.createCAIP10("eip155", "1", owner);
        bytes32 salt = keccak256(abi.encode(caip));
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKey,
            caip,
            ownerType
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(salt)));
        assertEq(
            smartAccountAddress,
            address(factory.computeSmartAccountAddress(caip))
        );
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        string memory caip = CAIP10.createCAIP10("eip155", "1", owner);
        factory.deploySmartAccount(
            ownerKey,
            caip,
            ownerType
        );

        vm.expectRevert("Account already exists");

        factory.deploySmartAccount(
            ownerKey,
            caip,
            ownerType
        );
    }

    // Test that the computed address matches the deployed address
    function testComputeSmartAccountAddress() public {
        string memory caip = CAIP10.createCAIP10("eip155", "1", owner);

        address smartAccountAddress = factory.deploySmartAccount(
            ownerKey,
            caip,
            ownerType
        );

        address computedAddress = factory.computeSmartAccountAddress(caip);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

    // Test deployment of smart account with NON-EVM
    function testDeploymentCreate2NonEVM() public {
        string memory caip = CAIP10.createSolanaCAIP10(
            solanaChainId,
            solanaAddress
        );
        bytes32 salt = keccak256(abi.encode(caip));

        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            ownerTypeNonEVM
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(salt)));
        assertEq(
            smartAccountAddress,
            address(factory.computeSmartAccountAddress(caip))
        );
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        string memory caip = CAIP10.createSolanaCAIP10(
            solanaChainId,
            solanaAddress
        );

        factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            ownerTypeNonEVM
        );

        vm.expectRevert("Account already exists");
        factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            ownerTypeNonEVM
        );
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeSmartAccountAddressNonEVM() public {
        string memory caip = CAIP10.createSolanaCAIP10(
            solanaChainId,
            solanaAddress
        );

        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            ownerTypeNonEVM
        );

        address computedAddress = factory.computeSmartAccountAddress(caip);

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }

}