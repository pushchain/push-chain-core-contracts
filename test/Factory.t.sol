// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {Errors} from "../src/libraries/Errors.sol";
import { AccountId, OwnerType } from "../src/libraries/Types.sol";

contract FactoryTest is Test {
    FactoryV1 factory;
    SmartAccountV1 smartAccount;

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerKey;

    address verifierPrecompile;
    OwnerType ownerType;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM;
    OwnerType ownerTypeNonEVM;
    string solanaChainId;
    string solanaAddress;

    function setUp() public {
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        // Set up user and keys
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerKey = abi.encodePacked(owner);

        // Set up verifier precompile
        verifierPrecompile = 0x0000000000000000000000000000000000000902;

        // Set up owner type
        ownerType = OwnerType.EVM;
        ownerTypeNonEVM = OwnerType.NON_EVM;

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
        AccountId memory _id = AccountId({
            namespace: "eip155",
            chainId: "1",
            ownerKey: ownerKey,
            ownerType: ownerType
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKey)));
        assertEq(
            smartAccountAddress,
            address(factory.computeSmartAccountAddress(ownerKey))
        );
    }

    // Test that the same account cannot be deployed twice
    function testDeploymentTwice() public {
        AccountId memory _id = AccountId({
            namespace: "eip155",
            chainId: "1",
            ownerKey: ownerKey,
            ownerType: ownerType
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        vm.expectRevert("Account already exists");

        factory.deploySmartAccount(_id);
    }

    // Test that the computed address matches the deployed address
    function testComputeSmartAccountAddress() public {
        AccountId memory _id = AccountId({
            namespace: "eip155",
            chainId: "1",
            ownerKey: ownerKey,
            ownerType: ownerType
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        address computedAddress = factory.computeSmartAccountAddress(ownerKey);

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
            ownerType: ownerTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);
        assertEq(smartAccountAddress, address(factory.userAccounts(ownerKeyNonEVM)));
        assertEq(
            smartAccountAddress,
            address(factory.computeSmartAccountAddress(ownerKeyNonEVM))
        );
    }

    // Test that the same account cannot be deployed twice with NON-EVM
    function testDeploymentTwiceNonEVM() public {
        AccountId memory _id = AccountId({
            namespace: "solana",
            chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            ownerKey: ownerKeyNonEVM,
            ownerType: ownerTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        vm.expectRevert("Account already exists");
        factory.deploySmartAccount(_id);
    }

    // Test that the computed address matches the deployed address with NON-EVM
    function testComputeSmartAccountAddressNonEVM() public {
        AccountId memory _id = AccountId({
            namespace: "solana",
            chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            ownerKey: ownerKeyNonEVM,
            ownerType: ownerTypeNonEVM
        });
        address smartAccountAddress = factory.deploySmartAccount(_id);

        address computedAddress = factory.computeSmartAccountAddress(
            ownerKeyNonEVM
        );

        console.log("Computed Address: ", computedAddress);
        console.log("Deployed Address: ", smartAccountAddress);

        assertEq(smartAccountAddress, computedAddress);
    }
}
