// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import { Target } from "../src/mocks/Target.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {CAIP10} from "./utils/caip.sol";

contract SmartAccountTest is Test {
    Target target;
    FactoryV1 factory;
    SmartAccountV1 smartAccount;

    // Set up the test environment - EVM
    address bob;
    uint256 bobPk;
    bytes bobKey;
    address verifierPrecompile = 0x1234567890123456789012345678901234567891;
    SmartAccountV1.OwnerType ownerType = SmartAccountV1.OwnerType.EVM;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM = hex"f1d234ab8473c0ab4f55ea1c7c3ea5feec4acb3b9498af9b63722c1b368b8e4c";
    SmartAccountV1.OwnerType ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;
    
    function setUp() public {
        target = new Target();
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        (bob, bobPk) = makeAddrAndKey("bob");
        bobKey = abi.encodePacked(address(bob));
    }

    function testImplementationAddress() public view {
        assertEq(address(factory.smartAccountImplementation()), address(smartAccount));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public{
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);
        bytes32 salt = keccak256(abi.encode(caip));

        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(salt)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(caip)));
    }

    // Test the state update of SmartAccount Post Deployment
    function testStateUpdate() public {
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);

        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(smartAccountAddress);
        
        console.logBytes(smartAccountInstance.ownerKey());
        console.log("Owner Key:", address(bytes20(bobKey)));
        console.log("Verifier Precompile:", smartAccountInstance.verifierPrecompile());
        console.log("Owner Type:", uint(smartAccountInstance.ownerType()));

        assertEq(smartAccountInstance.ownerKey(), bobKey);
        assertEq(address(smartAccountInstance.verifierPrecompile()), verifierPrecompile);
        assertEq(uint(smartAccountInstance.ownerType()), 0);
    }

    // Test the execution of a payload
    function testExecution() public{
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);
        // Deploy the smart account
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(smartAccountAddress);
        // prepare calldata for target contract
        bytes memory data = abi.encodeWithSignature("setMagicNumber(uint256)", 786);
        // sign the payload
        bytes32 messageHash = keccak256(data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // get magic value before execution
        uint256 magicValueBefore = target.getMagicNumber();
        console.log("Magic Value Before:", magicValueBefore);

        // execute the payload
        smartAccountInstance.executePayload(address(target), data, signature);
        // get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        console.log("Magic Value After:", magicValueAfter);
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
    }



}