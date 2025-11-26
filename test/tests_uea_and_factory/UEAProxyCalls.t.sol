// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/libraries/Types.sol";
import {Target} from "../../src/mocks/Target.sol";
import {UEAFactoryV1} from "../../src/uea/UEAFactoryV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {
    UniversalAccountId,
    UniversalPayload,
    VerificationType,
    UNIVERSAL_PAYLOAD_TYPEHASH
} from "../../src/libraries/Types.sol";

contract ProxyCallTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_EVM ueaEVMImpl;
    UEAProxy ueaProxyImpl;

    address user1;
    uint256 user1PK;
    bytes user1Bytes;
    address user1UEA;
    UEA_EVM user1UEAInstance;

    address user2;
    uint256 user2PK;
    bytes user2Bytes;
    address user2UEA;
    UEA_EVM user2UEAInstance;

    address admin;

    bytes32 constant EVM_HASH = keccak256("EVM");

    function setUp() public {
        target = new Target();
        admin = address(this);

        (user1, user1PK) = makeAddrAndKey("user1");
        user1Bytes = abi.encodePacked(user1);

        (user2, user2PK) = makeAddrAndKey("user2");
        user2Bytes = abi.encodePacked(user2);

        ueaEVMImpl = new UEA_EVM();
        ueaProxyImpl = new UEAProxy();

        UEAFactoryV1 factoryImpl = new UEAFactoryV1();

        bytes memory initData = abi.encodeWithSelector(UEAFactoryV1.initialize.selector, admin);
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(proxy));

        // Set UEAProxy implementation after initialization
        factory.setUEAProxyImplementation(address(ueaProxyImpl));

        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));

        UniversalAccountId memory user1Id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: user1Bytes});
        user1UEA = factory.deployUEA(user1Id);
        user1UEAInstance = UEA_EVM(payable(user1UEA));

        UniversalAccountId memory user2Id =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: user2Bytes});
        user2UEA = factory.deployUEA(user2Id);
        user2UEAInstance = UEA_EVM(payable(user2UEA));
    }

    // Test that UEA deployment correctly assigns the UniversalAccountId
    function testVerifyUEADeployment() public view {
        UniversalAccountId memory user1Account = user1UEAInstance.universalAccount();
        assertEq(user1Account.chainNamespace, "eip155");
        assertEq(user1Account.chainId, "1");
        assertEq(keccak256(user1Account.owner), keccak256(user1Bytes));

        UniversalAccountId memory user2Account = user2UEAInstance.universalAccount();
        assertEq(user2Account.chainNamespace, "eip155");
        assertEq(user2Account.chainId, "1");
        assertEq(keccak256(user2Account.owner), keccak256(user2Bytes));
    }

    // Test user1 can execute a transaction to set magic number
    function testUser1ExecuteSetMagicNumber() public {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        user1UEAInstance.executePayload(abi.encode(payload), signature);

        assertEq(target.getMagicNumber(), 123);
    }

    // Test user2 can execute a transaction after user1
    function testUser2ExecuteSetMagicNumber() public {
        testUser1ExecuteSetMagicNumber();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 456),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user2UEAInstance, payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user2PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        user2UEAInstance.executePayload(abi.encode(payload), signature);

        assertEq(target.getMagicNumber(), 456);
    }

    // Test user1 can execute a transaction with ETH value
    function testUser1ExecuteSetMagicNumberWithFee() public {
        vm.deal(user1UEA, 1 ether);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 789),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 targetBalanceBefore = address(target).balance;

        user1UEAInstance.executePayload(abi.encode(payload), signature);

        assertEq(target.getMagicNumber(), 789);
        assertEq(address(target).balance - targetBalanceBefore, 0.1 ether);
    }

    // Test user2 cannot execute with user1's signature
    function testUser2CannotExecuteWithUser1Signature() public {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        user2UEAInstance.executePayload(abi.encode(payload), signature);
    }

    // Test expired payload cannot be executed
    function testCannotExecuteExpiredPayload() public {
        vm.warp(1000);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: 500, // Expired deadline
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        user1UEAInstance.executePayload(abi.encode(payload), signature);
    }

    // Test nonce increments after execution
    function testNonceIncrementsAfterExecution() public {
        uint256 initialNonce = user1UEAInstance.nonce();
        assertEq(initialNonce, 0);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        user1UEAInstance.executePayload(abi.encode(payload), signature);

        uint256 newNonce = user1UEAInstance.nonce();
        assertEq(newNonce, initialNonce + 1);
    }

    // Test signature cannot be reused
    function testCannotReuseSignature() public {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        user1UEAInstance.executePayload(abi.encode(payload), signature);

        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        user1UEAInstance.executePayload(abi.encode(payload), signature);
    }

    // Test revert flow: User -> UEAProxy -> UEA_Implementation -> Target -> (revert) -> back to User
    function testRevertFlowFromTargetContract() public {
        vm.deal(user1UEA, 1 ether);

        // Create payload with incorrect fee amount (0.05 ETH instead of required 0.1 ETH)
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0.05 ether, // Incorrect fee amount, will cause Target to revert
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(user1UEAInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect the specific error from Target to bubble up through the proxy chain
        vm.expectRevert("Insufficient fee: 0.1 ETH required");
        user1UEAInstance.executePayload(abi.encode(payload), signature);
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
                uint8(payload.vType)
            )
        );

        bytes32 _domainSeparator = _smartAccountInstance.domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }
}
