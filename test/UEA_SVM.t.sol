// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {Target} from "../src/mocks/Target.sol";
import {UEAFactoryV1} from "../src/UEAFactoryV1.sol";
import {UEA_SVM} from "../src/UEA/UEA_SVM.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {ISmartAccount} from "../src/Interfaces/ISmartAccount.sol";
import {
    UniversalAccount, VM_TYPE, CrossChainPayload, PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH
} from "../src/libraries/Types.sol";

contract UEA_SVMTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_SVM ueaSVMImpl;
    UEA_SVM svmSmartAccountInstance;

    // Set up the test environment - SVM (Solana)
    bytes ownerKey;
    VM_TYPE vmType = VM_TYPE.SVM;
    string solanaAddress = "4HwuvaEVT4qnvb5TkSvMyYPrprqpnJjz8LSL6TPnuJ2U";
    string solanaChainId = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

    // Mock Ed25519 signature verification
    address constant VERIFIER_PRECOMPILE = 0x0000000000000000000000000000000000000901;

    function setUp() public {
        target = new Target();
        ueaSVMImpl = new UEA_SVM();

        // Create arrays for constructor - unused now
        address[] memory implementations = new address[](1);
        implementations[0] = address(ueaSVMImpl);

        uint256[] memory vmTypes = new uint256[](1);
        vmTypes[0] = uint256(VM_TYPE.SVM);

        // Deploy factory
        factory = new UEAFactoryV1();

        // Set up Solana key
        ownerKey = hex"30ea71869947818d27b718592ea44010b458903bd9bf0370f50eda79e87d9f69";

        // Register chain and implementation
        bytes32 svmChainHash = keccak256(abi.encode(solanaChainId));
        factory.registerNewChain(svmChainHash, VM_TYPE.SVM);
        factory.registerUEA(svmChainHash, address(ueaSVMImpl));
    }

    modifier deploySvmSmartAccount() {
        UniversalAccount memory _owner = UniversalAccount({CHAIN: solanaChainId, ownerKey: ownerKey});

        address smartAccountAddress = factory.deployUEA(_owner);
        svmSmartAccountInstance = UEA_SVM(payable(smartAccountAddress));
        _;
    }

    function testUEAImplementation() public view {
        bytes32 svmChainHash = keccak256(abi.encode(solanaChainId));
        assertEq(address(factory.getUEA(svmChainHash)), address(ueaSVMImpl));
    }

    function testUniversalAccount() public deploySvmSmartAccount {
        UniversalAccount memory account = svmSmartAccountInstance.universalAccount();
        assertEq(account.CHAIN, solanaChainId);
        assertEq(account.ownerKey, ownerKey);
    }

    function testDeploymentCreate2() public deploySvmSmartAccount {
        UniversalAccount memory _owner = UniversalAccount({CHAIN: solanaChainId, ownerKey: ownerKey});

        assertEq(address(svmSmartAccountInstance), address(factory.UOA_to_UEA(ownerKey)));
        assertEq(address(svmSmartAccountInstance), address(factory.computeUEA(_owner)));
    }

    function testExecution() public deploySvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = svmSmartAccountInstance.nonce();

        CrossChainPayload memory payload = CrossChainPayload({
            to: address(target),
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
        emit ISmartAccount.PayloadExecuted(ownerKey, payload.to, payload.data);

        // Execute the payload
        svmSmartAccountInstance.executePayload(payload, signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, svmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    function testRevertWhenInvalidSignature() public deploySvmSmartAccount {
        CrossChainPayload memory payload = CrossChainPayload({
            to: address(target),
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

    function testRevertWhenPrecompileFails() public deploySvmSmartAccount {
        CrossChainPayload memory payload = CrossChainPayload({
            to: address(target),
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

    function testRevertWhenExpiredDeadline() public deploySvmSmartAccount {
        // Increase timestamp to 100th block
        vm.warp(block.timestamp + 100);

        CrossChainPayload memory payload = CrossChainPayload({
            to: address(target),
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
            to: address(target),
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
    function getCrosschainTxhash(UEA_SVM _smartAccountInstance, CrossChainPayload memory payload)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PUSH_CROSS_CHAIN_PAYLOAD_TYPEHASH,
                payload.to,
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
