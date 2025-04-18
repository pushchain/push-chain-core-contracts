// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import { Target } from "../src/mocks/Target.sol";
import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccountV1.sol";

contract SmartAccountTest is Test {
    Target target;
    FactoryV1 factory;
    SmartAccountV1 smartAccount;

    // Set up the test environment - EVM
    address bob;
    uint256 bobPk;
    bytes bobKey;
    address verifierPrecompile = 0x0000000000000000000000000000000000000902;
    SmartAccountV1.OwnerType ownerType = SmartAccountV1.OwnerType.EVM;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";
    SmartAccountV1.OwnerType ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;
    
    function setUp() public {
        target = new Target();
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        (bob, bobPk) = makeAddrAndKey("bob");
        bobKey = abi.encodePacked(address(bob));
    }

    function testImplementationAddress() public {
        assertEq(address(factory.smartAccountImplementation()), address(smartAccount));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public{
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            ownerType,
            verifierPrecompile
        );
        assertEq(smartAccountAddress, address(factory.userAccounts(bobKey)));
        assertEq(smartAccountAddress, address(factory.computeSmartAccountAddress(bobKey)));
    }

    // Test the state update of SmartAccount Post Deployment
    function testStateUpdate() public {
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
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
        // Deploy the smart account
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
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

    function testNonEVMExecution() public {
        // Deploy the smart account
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            ownerTypeNonEVM,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(smartAccountAddress);
        
        // Calldata and signature for target contract
        bytes memory data = '0x2ba2ed980000000000000000000000000000000000000000000000000000000000000312';
        bytes memory signature = '0x16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03';

        // Get magic value before execution
        uint256 magicValueBefore = target.getMagicNumber();
        console.log("Magic Value Before:", magicValueBefore);

        // Execute the payload using the smart account instance
        smartAccountInstance.executePayload(address(target), data, signature);
        
        // Get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        console.log("Magic Value After:", magicValueAfter);
        
        // Assert the magic value was set correctly
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
    }

    function testVerifyEd25519Precompile() public {
        bytes memory pubkey = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";
        bytes memory message = hex"2ba2ed980000000000000000000000000000000000000000000000000000000000000312";
        bytes memory signature = hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Perform staticcall
        (bool success, bytes memory result) = address(0x902).staticcall(
            abi.encodeWithSignature("verifyEd25519(bytes,bytes,bytes)", pubkey, message, signature)
        );

        require(success, "Precompile call failed");

        bool verified = abi.decode(result, (bool));
        assertTrue(verified, "Signature should be valid");
    }
}