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

    // Relayer Setup
    address relayer;
    uint256 relayerPk;

    // Set up the test environment - EVM
    address bob;
    uint256 bobPk;
    bytes bobKey;
    address verifierPrecompile = 0x0000000000000000000000000000000000000902;
    SmartAccountV1.OwnerType ownerType = SmartAccountV1.OwnerType.EVM;

    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";
    SmartAccountV1.OwnerType ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;
    string solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    string solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

    // Set up BOB CAIP and CallData
    string caip = CAIP10.createCAIP10("eip155", "1", bob);
    bytes callData = abi.encodeWithSignature("setMagicNumber(uint256)", 786);

    function setUp() public {
        target = new Target();
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));


        relayerPk = vm.envUint("RELAYER_PRIVATE_KEY");
        bobPk = vm.envUint("BOB_PRIVATE_KEY");

        bob = vm.addr(bobPk);
        relayer = vm.addr(relayerPk);
        bobKey = abi.encodePacked(address(bob));




        // Labeling accounts for easier debugging
        vm.label(relayer, "Relayer");
        vm.label(bob, "Bob");
        vm.label(address(factory), "Factory");
        vm.label(address(target), "Target");
        vm.label(address(smartAccount), "SmartAccount");
    }

    function testImplementationAddress() public view {
        assertEq(address(factory.smartAccountImplementation()), address(smartAccount));
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public{
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
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(payable(smartAccountAddress));
        
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
            caip,
            ownerType,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(payable(smartAccountAddress));

        bytes32 messageHash = keccak256(callData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, messageHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // get magic value before execution
        uint256 magicValueBefore = target.getMagicNumber();
        console.log("Magic Value Before:", magicValueBefore);

        // Payload to be executed by relayer
        vm.startPrank(relayer);
        // execute the payload
        smartAccountInstance.executePayload(address(target), callData, signature);

        vm.stopPrank();
        // get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        console.log("Magic Value After:", magicValueAfter);
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
    }

    // Test the execution of a payload with refund
    function testExecutionWithRefund() public {
        // Deploy the smart account
        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        vm.deal(address(smartAccountAddress), 5 ether);

        SmartAccountV1 smartAccountInstance = SmartAccountV1(payable(smartAccountAddress));
        // sign the payload
        bytes32 messageHash = keccak256(callData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);


        // relayer balance before execution
        uint256 relayerBalanceBefore = relayer.balance;
        console.log("Relayer Balance Before:", relayerBalanceBefore);
        uint256 contractBalanceBefore = smartAccountAddress.balance;
        console.log("Contract Balance Before:", contractBalanceBefore);

        // Payload to be executed
        vm.txGasPrice(1 gwei);
        vm.startPrank(relayer);

        smartAccountInstance.executePayload(
            address(target),
            callData,
            signature
        );


        // relayer balance after execution
        uint256 relayerBalanceAfter = relayer.balance;
        console.log("Relayer Balance After:", relayerBalanceAfter);
        uint256 contractBalanceAfter = smartAccountAddress.balance;
        console.log("Contract Balance After:", contractBalanceAfter);
        //assertEq(relayerBalanceAfter, , "Relayer was not refunded correctly");
        vm.stopPrank();
    }
}