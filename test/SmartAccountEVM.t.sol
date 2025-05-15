// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {Target} from "../src/mocks/Target.sol";
import {FactoryV1} from "../src/FactoryV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SmartAccountEVM} from "../src/smartAccounts/SmartAccountEVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {ISmartAccount} from "../src/Interfaces/ISmartAccount.sol";
import {AccountId, VM_TYPE, CrossChainPayload, PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH} from "../src/libraries/Types.sol";

contract SmartAccountEVMTest is Test {
    Target target;
    FactoryV1 factory;
    SmartAccountEVM smartAccountEVMImpl;
    SmartAccountEVM evmSmartAccountInstance;

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerKey;
    VM_TYPE vmType = VM_TYPE.EVM;

    function setUp() public {
        target = new Target();
        smartAccountEVMImpl = new SmartAccountEVM();

        // Create arrays for constructor
        address[] memory implementations = new address[](1);
        implementations[0] = address(smartAccountEVMImpl);

        uint256[] memory vmTypes = new uint256[](1);
        vmTypes[0] = uint256(VM_TYPE.EVM);

        // Deploy factory with EVM implementation
        factory = new FactoryV1(implementations, vmTypes);

        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerKey = abi.encodePacked(owner);
    }

    modifier deployEvmSmartAccount() {
        AccountId memory _owner = AccountId({namespace: "eip155", chainId: "1", ownerKey: ownerKey, vmType: vmType});

        address smartAccountAddress = factory.deploySmartAccount(_owner);
        evmSmartAccountInstance = SmartAccountEVM(payable(smartAccountAddress));
        _;
    }

    function testImplementationAddress() public view {
        assertEq(address(factory.getImplementation(VM_TYPE.EVM)), address(smartAccountEVMImpl));
    }

    function testAccountId() public deployEvmSmartAccount {
        AccountId memory accountId = evmSmartAccountInstance.accountId();
        assertEq(accountId.namespace, "eip155");
        assertEq(accountId.chainId, "1");
        assertEq(accountId.ownerKey, ownerKey);
        assertEq(uint256(accountId.vmType), uint256(VM_TYPE.EVM));
    }

    function testDeploymentCreate2() public deployEvmSmartAccount {
        AccountId memory _owner = AccountId({namespace: "eip155", chainId: "1", ownerKey: ownerKey, vmType: vmType});

        assertEq(address(evmSmartAccountInstance), address(factory.userAccounts(ownerKey)));

        assertEq(address(evmSmartAccountInstance), address(factory.computeSmartAccountAddress(_owner)));
    }

    function testRevert_WhenIncorrectNonce() public deployEvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = evmSmartAccountInstance.nonce();

        CrossChainPayload memory payload = CrossChainPayload({
            target: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 100, // Incorrect nonce
            deadline: block.timestamp + 1000
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);

        // Sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(Errors.InvalidEVMSignature.selector));
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state hasn't changed
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 0, "Magic value should not have changed");
        assertEq(previousNonce, evmSmartAccountInstance.nonce(), "Nonce should not have changed");
    }

    function testExecution() public deployEvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = evmSmartAccountInstance.nonce();

        CrossChainPayload memory payload = CrossChainPayload({
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

        // Sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, true);
        emit ISmartAccount.PayloadExecuted(ownerKey, payload.target, payload.data);

        // Execute the payload
        evmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, evmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    function testRevert_WhenSameNonceUsed() public deployEvmSmartAccount {
        // First execution
        CrossChainPayload memory payload = CrossChainPayload({
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

    function testRevert_WhenExpiredDeadline() public deployEvmSmartAccount {
        // Increase timestamp to 100th block
        vm.warp(block.timestamp + 100);

        CrossChainPayload memory payload = CrossChainPayload({
            target: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp - 1 // Expired deadline
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        evmSmartAccountInstance.executePayload(payload, signature);
    }

    function testRevert_WhenInvalidSignature() public deployEvmSmartAccount {
        CrossChainPayload memory payload = CrossChainPayload({
            target: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000
        });

        // Create an invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignature.selector));
        evmSmartAccountInstance.executePayload(payload, invalidSignature);
    }

    function testExecutionWithValue() public deployEvmSmartAccount {
        // Fund the smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        CrossChainPayload memory payload = CrossChainPayload({
            target: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000
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

    // Helper function for CrossChainPayload hash
    function getCrosschainTxhash(SmartAccountEVM _smartAccountInstance, CrossChainPayload memory payload)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                payload.target,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                payload.nonce,
                payload.deadline
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", _smartAccountInstance.domainSeparator(), structHash));
    }
}
