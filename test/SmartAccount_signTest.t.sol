// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {Target} from "../src/mocks/Target.sol";
import {FactoryV1} from "../src/SmartAccount/FactoryV1.sol";
import {SmartAccountV1} from "../src/SmartAccount/SmartAccountV1.sol";
import {CAIP10} from "./utils/caip.sol";

contract SmartAccountTest is Test {
    Target target;
    FactoryV1 factory;
    SmartAccountV1 smartAccount;
    SmartAccountV1 evmSmartAccountInstance;
    // Set up the test environment - EVM
    address bob;
    uint256 bobPk;
    bytes bobKey;
    address verifierPrecompile = 0x0000000000000000000000000000000000000902;
    SmartAccountV1.OwnerType ownerType = SmartAccountV1.OwnerType.EVM;

    bytes32 private constant PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH =
        keccak256(
            "CrossChainPayload(address target,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)"
        );
    // Set up the test environment - NON-EVM
    bytes ownerKeyNonEVM =
        hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";
    SmartAccountV1.OwnerType ownerTypeNonEVM = SmartAccountV1.OwnerType.NON_EVM;
    string solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    string solanaAddress = "HGyAQb8SeAE6X6RfhgMpGWZQuVYU8kgA5tKitaTrUHfh";

    function setUp() public {
        target = new Target();
        smartAccount = new SmartAccountV1();
        factory = new FactoryV1(address(smartAccount));

        (bob, bobPk) = makeAddrAndKey("bob");
        bobKey = abi.encodePacked(address(bob));
    }

    function testImplementationAddress() public view {
        assertEq(
            address(factory.smartAccountImplementation()),
            address(smartAccount)
        );
    }

    modifier deployEvmSmartAccount() {
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);

        address smartAccountAddress = factory.deploySmartAccount(
            bobKey,
            caip,
            ownerType,
            verifierPrecompile
        );
        evmSmartAccountInstance = SmartAccountV1(payable(smartAccountAddress));
        _;
    }

    // Test deployment of smart account
    function testDeploymentCreate2() public deployEvmSmartAccount {
        string memory caip = CAIP10.createCAIP10("eip155", "1", bob);
        bytes32 salt = keccak256(abi.encode(caip));

        assertEq(
            address(evmSmartAccountInstance),
            address(factory.userAccounts(salt))
        );
        assertEq(
            address(evmSmartAccountInstance),
            address(factory.computeSmartAccountAddress(caip))
        );
    }

    // Test the state update of SmartAccount Post Deployment
    function testStateUpdate() public deployEvmSmartAccount {
        console.logBytes(evmSmartAccountInstance.ownerKey());
        console.log("Owner Key:", address(bytes20(bobKey)));
        console.log(
            "Verifier Precompile:",
            evmSmartAccountInstance.verifierPrecompile()
        );
        console.log("Owner Type:", uint(evmSmartAccountInstance.ownerType()));

        assertEq(evmSmartAccountInstance.ownerKey(), bobKey);
        assertEq(
            address(evmSmartAccountInstance.verifierPrecompile()),
            verifierPrecompile
        );
        assertEq(uint(evmSmartAccountInstance.ownerType()), 0);
    }

    //When nonce is incorrect
    function testRevet_whenIncorrectNonce() public deployEvmSmartAccount {
        // prepare calldata for target contract
        SmartAccountV1.CrossChainPayload memory payload = SmartAccountV1
            .CrossChainPayload({
                target: address(target),
                value: 0,
                data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
                gasLimit: 1000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                nonce: 1, //incorrect nonce
                deadline: block.timestamp + 1000
            });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        // sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, txHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid EVM signature");
        // execute the payload
        evmSmartAccountInstance.executePayload(payload, signature);
        // get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 0, "Magic value was not set correctly");
    }

    // Test the execution of a payload
    function testExecution() public deployEvmSmartAccount {
        // prepare calldata for target contract
        SmartAccountV1.CrossChainPayload memory payload = SmartAccountV1
            .CrossChainPayload({
                target: address(target),
                value: 0,
                data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
                gasLimit: 1000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                nonce: 0,
                deadline: block.timestamp + 1000
            });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        // sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, txHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, true);
        emit SmartAccountV1.PayloadExecuted(
            bobKey,
            payload.target,
            payload.data
        );
        // execute the payload
        evmSmartAccountInstance.executePayload(payload, signature);
        // get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
    }

    // Test the execution of a payload
    function testRevert_WhenSameNonceused() public {
        testExecution();
        // prepare calldata for target contract
        SmartAccountV1.CrossChainPayload memory payload = SmartAccountV1
            .CrossChainPayload({
                target: address(target),
                value: 0,
                data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
                gasLimit: 1000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                nonce: 0,
                deadline: block.timestamp + 1000
            });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        // sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, txHash);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid EVM signature"); // execute the payload

        evmSmartAccountInstance.executePayload(payload, signature); // get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
    }

    function testNonEVMExecution() public {
        string memory caip = CAIP10.createSolanaCAIP10(
            solanaChainId,
            solanaAddress
        );
        bytes32 salt = keccak256(abi.encode(caip));

        // Deploy the smart account
        address smartAccountAddress = factory.deploySmartAccount(
            ownerKeyNonEVM,
            caip,
            ownerTypeNonEVM,
            verifierPrecompile
        );
        SmartAccountV1 smartAccountInstance = SmartAccountV1(
            payable(smartAccountAddress)
        );

        SmartAccountV1.CrossChainPayload memory payload = SmartAccountV1
            .CrossChainPayload({
                target: address(target),
                value: 0,
                data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
                gasLimit: 1000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                nonce: 1,
                deadline: block.timestamp + 1000
            });

        // Calldata and signature for target contract
        bytes
            memory signature = "0x16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Get magic value before execution
        uint256 magicValueBefore = target.getMagicNumber();
        console.log("Magic Value Before:", magicValueBefore);

        // Execute the payload using the smart account instance
        smartAccountInstance.executePayload(payload, signature);

        // Get magic value after execution
        uint256 magicValueAfter = target.getMagicNumber();
        console.log("Magic Value After:", magicValueAfter);

        // Assert the magic value was set correctly
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(smartAccountAddress, address(factory.userAccounts(salt)));
    }

    function testVerifyEd25519Precompile() public {
        bytes
            memory pubkey = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";
        bytes
            memory message = hex"2ba2ed980000000000000000000000000000000000000000000000000000000000000312";
        bytes
            memory signature = hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Perform staticcall
        (bool success, bytes memory result) = address(0x902).staticcall(
            abi.encodeWithSignature(
                "verifyEd25519(bytes,bytes,bytes)",
                pubkey,
                message,
                signature
            )
        );

        require(success, "Precompile call failed");

        bool verified = abi.decode(result, (bool));
        assertTrue(verified, "Signature should be valid");
    }

    //helper function for CrossChainPayload hash

    function getCrosschainTxhash(
        SmartAccountV1 _smartAccountInstance,
        SmartAccountV1.CrossChainPayload memory payload
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                address(target), // Target contract address to call
                payload.value, // Native token amount to send
                keccak256(payload.data), // Call data for the function execution
                payload.gasLimit, // Maximum gas to be used for this tx (caps refund amount)
                payload.maxFeePerGas, // Maximum fee per gas unit
                payload.maxPriorityFeePerGas, // Maximum priority fee per gas unit
                payload.nonce, // Chain ID where this should be executed
                payload.deadline
            )
        );
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    _smartAccountInstance.domainSeparator(),
                    structHash
                )
            );
    }
}
