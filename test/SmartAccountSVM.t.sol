// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {Target} from "../src/mocks/Target.sol";
import {FactoryV1} from "../src/FactoryV1.sol";
import {SmartAccountSVM} from "../src/smartAccounts/SmartAccountSVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {ISmartAccount} from "../src/Interfaces/ISmartAccount.sol";
import {AccountId, VM_TYPE, CrossChainPayload, PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH} from "../src/libraries/Types.sol";

contract SmartAccountSVMTest is Test {
    Target target;
    FactoryV1 factory;
    SmartAccountSVM smartAccountSVMImpl;
    SmartAccountSVM svmSmartAccountInstance;

    // Set up the test environment - SVM (Solana)
    bytes ownerKey;
    VM_TYPE vmType = VM_TYPE.SVM;
    string solanaAddress = "4HwuvaEVT4qnvb5TkSvMyYPrprqpnJjz8LSL6TPnuJ2U";
    string solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

    // Mock Ed25519 signature verification
    address constant VERIFIER_PRECOMPILE = 0x0000000000000000000000000000000000000901;

    function setUp() public {
        target = new Target();
        smartAccountSVMImpl = new SmartAccountSVM();

        // Create arrays for constructor
        address[] memory implementations = new address[](1);
        implementations[0] = address(smartAccountSVMImpl);

        uint256[] memory vmTypes = new uint256[](1);
        vmTypes[0] = uint256(VM_TYPE.SVM);

        // Deploy factory with SVM implementation
        factory = new FactoryV1(implementations, vmTypes);

        // Set up Solana key
        ownerKey = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";

        // // Mock the precompile verification
        // vm.etch(VERIFIER_PRECOMPILE, hex"00");
        // vm.mockCall(
        //     VERIFIER_PRECOMPILE,
        //     abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerKey, bytes32(0), bytes("")),
        //     abi.encode(true)
        // );
    }

    modifier deploySvmSmartAccount() {
        AccountId memory _owner =
            AccountId({namespace: "solana", chainId: solanaChainId, ownerKey: ownerKey, vmType: vmType});

        address smartAccountAddress = factory.deploySmartAccount(_owner);
        svmSmartAccountInstance = SmartAccountSVM(payable(smartAccountAddress));
        _;
    }

    function testImplementationAddress() public view {
        assertEq(address(factory.getImplementation(VM_TYPE.SVM)), address(smartAccountSVMImpl));
    }

    function testAccountId() public deploySvmSmartAccount {
        AccountId memory accountId = svmSmartAccountInstance.accountId();
        assertEq(accountId.namespace, "solana");
        assertEq(accountId.chainId, solanaChainId);
        assertEq(accountId.ownerKey, ownerKey);
        assertEq(uint256(accountId.vmType), uint256(VM_TYPE.SVM));
    }

    function testDeploymentCreate2() public deploySvmSmartAccount {
        AccountId memory _owner =
            AccountId({namespace: "solana", chainId: solanaChainId, ownerKey: ownerKey, vmType: vmType});

        assertEq(address(svmSmartAccountInstance), address(factory.userAccounts(ownerKey)));

        assertEq(address(svmSmartAccountInstance), address(factory.computeSmartAccountAddress(_owner)));
    }

    function testExecution() public deploySvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = svmSmartAccountInstance.nonce();

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

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);

        // Create a mock Ed25519 signature
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerKey, txHash, signature),
            abi.encode(true)
        );

        vm.expectEmit(true, true, true, true);
        emit ISmartAccount.PayloadExecuted(ownerKey, payload.target, payload.data);

        // Execute the payload
        svmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, svmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    function testRevert_WhenInvalidSignature() public deploySvmSmartAccount {
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

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);

        // Create a signature
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to return false
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerKey, txHash, signature),
            abi.encode(false)
        );

        vm.expectRevert(Errors.InvalidSVMSignature.selector);
        svmSmartAccountInstance.executePayload(payload, signature);
    }

    function testRevert_WhenPrecompileFails() public deploySvmSmartAccount {
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

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);

        // Create a signature
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to revert
        vm.mockCallRevert(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerKey, txHash, signature),
            "Precompile error"
        );

        vm.expectRevert(Errors.PrecompileCallFailed.selector);
        svmSmartAccountInstance.executePayload(payload, signature);
    }

    function testRevert_WhenExpiredDeadline() public deploySvmSmartAccount {
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

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        svmSmartAccountInstance.executePayload(payload, signature);
    }

    function testExecutionWithValue() public deploySvmSmartAccount {
        // Fund the smart account
        vm.deal(address(svmSmartAccountInstance), 1 ether);

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

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerKey, txHash, signature),
            abi.encode(true)
        );

        // Execute the payload
        svmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 999, "Magic value was not set correctly");
        assertEq(address(target).balance, 0.1 ether, "Target contract should have received 0.1 ETH");
    }

    // Helper function for CrossChainPayload hash
    function getCrosschainTxhash(SmartAccountSVM _smartAccountInstance, CrossChainPayload memory payload)
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
                _smartAccountInstance.nonce(),
                payload.deadline
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", _smartAccountInstance.domainSeparator(), structHash));
    }
}
