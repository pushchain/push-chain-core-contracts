// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/libraries/Types.sol";
import {Target} from "../src/mocks/Target.sol";
import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UEA_EVM} from "../src/UEA/UEA_EVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {IUEA} from "../src/Interfaces/IUEA.sol";

contract UEA_EVMTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_EVM ueaEVMImpl;
    UEA_EVM evmSmartAccountInstance;

    // VM Hash constants
    bytes32 constant EVM_HASH = keccak256("EVM");

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerBytes;

    function setUp() public {
        target = new Target();
        ueaEVMImpl = new UEA_EVM();

        // Deploy factory
        factory = new UEAFactoryV1();

        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        // Register EVM chain and implementation
        bytes32 evmChainHash = keccak256(abi.encode("ETHEREUM"));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));
    }

    modifier deployEvmSmartAccount() {
        UniversalAccount memory _owner = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});

        address smartAccountAddress = factory.deployUEA(_owner);
        evmSmartAccountInstance = UEA_EVM(payable(smartAccountAddress));
        _;
    }

    function testUEAImplementation() public view {
        bytes32 evmChainHash = keccak256(abi.encode("ETHEREUM"));
        assertEq(address(factory.getUEA(evmChainHash)), address(ueaEVMImpl));
    }

    function testUniversalAccount() public deployEvmSmartAccount {
        UniversalAccount memory account = evmSmartAccountInstance.universalAccount();
        assertEq(account.chain, "ETHEREUM");
        assertEq(account.owner, ownerBytes);
    }

    function testDeploymentCreate2() public deployEvmSmartAccount {
        UniversalAccount memory _owner = UniversalAccount({chain: "ETHEREUM", owner: ownerBytes});
        bytes32 salt = factory.generateSalt(_owner);
        assertEq(address(evmSmartAccountInstance), address(factory.UOA_to_UEA(salt)));
        assertEq(address(evmSmartAccountInstance), address(factory.computeUEA(_owner)));
    }

    function testRevertWhenIncorrectNonce() public deployEvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = evmSmartAccountInstance.nonce();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 100, // Incorrect nonce
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        // Create a signature - Note: The nonce in the payload and the nonce used in getTransactionHash need to match
        // for the test to work properly. We're getting the transaction hash with payload.nonce, not with the account's nonce
        bytes32 txHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                evmSmartAccountInstance.domainSeparator(),
                keccak256(
                    abi.encode(
                        UNIVERSAL_PAYLOAD_TYPEHASH,
                        payload.to,
                        payload.value,
                        keccak256(payload.data),
                        payload.gasLimit,
                        payload.maxFeePerGas,
                        payload.maxPriorityFeePerGas,
                        payload.nonce, // Using payload nonce, not account nonce
                        payload.deadline,
                        uint8(payload.sigType)
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // The execution should fail because the account expects nonce to be 0, not 100
        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state hasn't changed
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 0, "Magic value should not have changed");
        assertEq(previousNonce, evmSmartAccountInstance.nonce(), "Nonce should not have changed");
    }

    function testExecution() public deployEvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = evmSmartAccountInstance.nonce();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);

        // Sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, true);
        emit IUEA.PayloadExecuted(ownerBytes, payload.to, payload.data);

        // Execute the payload
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, evmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    function testRevertWhenSameNonceUsed() public deployEvmSmartAccount {
        // First execution
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First execution should succeed
        evmSmartAccountInstance.executePayload(payload, signature);

        uint256 previousNonce = evmSmartAccountInstance.nonce();

        // Try to execute with same nonce again
        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state hasn't changed
        assertEq(previousNonce, evmSmartAccountInstance.nonce(), "Nonce should not have changed");
    }

    function testRevertWhenExpiredDeadline() public deployEvmSmartAccount {
        // Increase timestamp to 100th block
        vm.warp(block.timestamp + 100);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp - 1, // Expired deadline
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        evmSmartAccountInstance.executePayload(payload, signature);
    }

    function testRevertWhenInvalidSignature() public deployEvmSmartAccount {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        // Create an invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignature.selector));
        evmSmartAccountInstance.executePayload(payload, invalidSignature);
    }

    function testExecutionWithValue() public deployEvmSmartAccount {
        // Fund the smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            sigType: SignatureType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 999, "Magic value was not set correctly");
        assertEq(address(target).balance, 0.1 ether, "Target contract should have received 0.1 ETH");
    }

    // Helper function for UniversalPayload hash
    function getCrosschainTxhash(UEA_EVM _smartAccountInstance, UniversalPayload memory payload)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                UNIVERSAL_PAYLOAD_TYPEHASH,
                payload.to,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                _smartAccountInstance.nonce(),
                payload.deadline,
                uint8(payload.sigType)
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = _smartAccountInstance.domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }
}
