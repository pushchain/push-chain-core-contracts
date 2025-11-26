// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/libraries/Types.sol";
import {Target} from "../../src/mocks/Target.sol";
import {UEAFactoryV1} from "../../src/uea/UEAFactoryV1.sol";
import {UEA_SVM} from "../../src/uea/UEA_SVM.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAMigration} from "../../src/uea/UEAMigration.sol";

contract UEASVMTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_SVM svmSmartAccountImpl;
    UEA_SVM svmSmartAccountInstance;
    UEAProxy ueaProxyImpl;
    UEA_EVM ueaEVMImpl;
    UEA_SVM ueaSVMImpl2;
    UEAMigration migration;

    // VM Hash constants
    bytes32 constant SVM_HASH = keccak256("SVM");

    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    // Set up the test environment - SVM
    bytes ownerBytes = hex"e48f4e93ca594d3c5e09c3ad39c599bbd6e6a2937869f3456905f5aeb7c78a60"; // Placeholder Solana public key
    address constant VERIFIER_PRECOMPILE = 0x00000000000000000000000000000000000000ca;

    function setUp() public {
        target = new Target();

        // Deploy UEAProxy implementation
        ueaProxyImpl = new UEAProxy();

        // Deploy the factory implementation
        UEAFactoryV1 factoryImpl = new UEAFactoryV1();

        // Deploy and initialize the proxy with initialOwner
        bytes memory initData = abi.encodeWithSelector(UEAFactoryV1.initialize.selector, address(this));
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactoryV1(address(proxy));

        // Set UEAProxy implementation after initialization
        factory.setUEAProxyImplementation(address(ueaProxyImpl));

        // Deploy SVM implementation
        svmSmartAccountImpl = new UEA_SVM();

        // Register SVM chain and implementation
        bytes32 svmChainHash = keccak256(abi.encode("solana", "101"));
        factory.registerNewChain(svmChainHash, SVM_HASH);
        factory.registerUEA(svmChainHash, SVM_HASH, address(svmSmartAccountImpl));

        // Deploy UEAMigration with both impls
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl2 = new UEA_SVM();
        migration = new UEAMigration(address(ueaEVMImpl), address(ueaSVMImpl2));
    }

    modifier deploySvmSmartAccount() {
        UniversalAccountId memory _owner =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: ownerBytes});

        address smartAccountAddress = factory.deployUEA(_owner);
        svmSmartAccountInstance = UEA_SVM(payable(smartAccountAddress));
        _;
    }

    // =========================================================================
    // Initialize and Setup Tests
    // =========================================================================

    function testInitializeFunction() public {
        // Deploy a new implementation without using the factory
        UEA_SVM newUEA = new UEA_SVM();

        // Create account ID
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: ownerBytes});

        // Initialize the account
        newUEA.initialize(_id);

        // Verify account details were set correctly
        UniversalAccountId memory storedId = newUEA.universalAccount();
        assertEq(storedId.chainNamespace, _id.chainNamespace);
        assertEq(storedId.chainId, _id.chainId);
        assertEq(keccak256(storedId.owner), keccak256(_id.owner));
    }

    function testRevertWhenInitializingTwice() public {
        // Deploy a new implementation without using the factory
        UEA_SVM newUEA = new UEA_SVM();

        // Create account ID
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: ownerBytes});

        // Initialize the account
        newUEA.initialize(_id);

        // Try to initialize again with the same ID
        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        newUEA.initialize(_id);

        // Try to initialize again with a different ID
        bytes memory differentOwnerBytes = hex"a48f4e93ca594d3c5e09c3ad39c599bbd6e6a2937869f3456905f5aeb7c78a61";
        UniversalAccountId memory differentId =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: differentOwnerBytes});

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        newUEA.initialize(differentId);
    }

    function testRegisterChain() public view {
        bytes32 svmChainHash = keccak256(abi.encode("solana", "101"));
        (bytes32 vmHash, bool isRegistered) = factory.getVMType(svmChainHash);
        assertEq(vmHash, SVM_HASH);
        assertTrue(isRegistered);
    }

    function testDeployUEA() public deploySvmSmartAccount {
        assertTrue(factory.hasCode(address(svmSmartAccountInstance)));
    }

    function testVersionConstant() public {
        // Deploy a new implementation
        UEA_SVM newUEA = new UEA_SVM();

        // Check the version constant
        assertEq(newUEA.VERSION(), "1.0.0", "VERSION constant should be 1.0.0");
    }

    function testVerifierPrecompileConstant() public {
        // Deploy a new implementation
        UEA_SVM newUEA = new UEA_SVM();

        // Check the VERIFIER_PRECOMPILE constant
        assertEq(
            newUEA.VERIFIER_PRECOMPILE(),
            0x00000000000000000000000000000000000000ca,
            "VERIFIER_PRECOMPILE constant should be 0x00000000000000000000000000000000000000ca"
        );
    }

    // =========================================================================
    // Public Functions Tests
    // =========================================================================

    function testUniversalAccount() public deploySvmSmartAccount {
        UniversalAccountId memory account = svmSmartAccountInstance.universalAccount();
        assertEq(account.chainNamespace, "solana");
        assertEq(account.owner, ownerBytes);
    }

    function testMockVerifySignature() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to return true for this signature
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            abi.encode(true)
        );

        bool verified = svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
        assertTrue(verified);
    }

    function testVerifySignatureFalse() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to return false for this signature
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            abi.encode(false)
        );

        bool verified = svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
        assertFalse(verified);
    }

    function testVerifySignatureRevert() public deploySvmSmartAccount {
        bytes32 messageHash = keccak256("test message");
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verifier precompile to revert
        vm.mockCallRevert(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, messageHash, signature),
            "Precompile error"
        );

        vm.expectRevert(Errors.PrecompileCallFailed.selector);
        svmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
    }

    // =========================================================================
    // Verify Payload TxHash Tests
    // =========================================================================
    // Note: mock calls are used to test the TX_BASED_VERIFIER precompile call.
    function testVerifyPayloadTxHashSuccess() public deploySvmSmartAccount {
        // Create a message hash
        bytes32 payloadHash = keccak256(abi.encodePacked("test payload hash"));

        // Mock txHash verification data
        bytes memory txHash = abi.encodePacked("mock_tx_hash_data");

        // Mock the TX_BASED_VERIFIER precompile to return true
        vm.mockCall(
            svmSmartAccountInstance.TX_BASED_VERIFIER(),
            abi.encodeWithSignature(
                "verifyTxHash(string,string,bytes,bytes32,bytes)",
                svmSmartAccountInstance.universalAccount().chainNamespace,
                svmSmartAccountInstance.universalAccount().chainId,
                svmSmartAccountInstance.universalAccount().owner,
                payloadHash,
                txHash
            ),
            abi.encode(true)
        );

        // Verify the txHash is valid
        bool isValid = svmSmartAccountInstance.verifyPayloadTxHash(payloadHash, txHash);
        assertTrue(isValid, "TxHash verification should succeed when precompile returns true");
    }

    // Test for verifyPayloadTxHash with precompile failure
    function testVerifyPayloadTxHashPrecompileFailure() public deploySvmSmartAccount {
        // Create a message hash
        bytes32 payloadHash = keccak256(abi.encodePacked("test payload hash"));

        // Mock txHash verification data
        bytes memory txHash = abi.encodePacked("mock_tx_hash_data");

        // Mock the TX_BASED_VERIFIER precompile to revert
        vm.mockCallRevert(
            svmSmartAccountInstance.TX_BASED_VERIFIER(),
            abi.encodeWithSignature(
                "verifyTxHash(string,string,bytes,bytes32,bytes)",
                svmSmartAccountInstance.universalAccount().chainNamespace,
                svmSmartAccountInstance.universalAccount().chainId,
                svmSmartAccountInstance.universalAccount().owner,
                payloadHash,
                txHash
            ),
            "Precompile error"
        );

        // Expect revert when precompile call fails
        vm.expectRevert(Errors.PrecompileCallFailed.selector);
        svmSmartAccountInstance.verifyPayloadTxHash(payloadHash, txHash);
    }

    // Test executePayload with txBased verification success
    function testExecutionWithTxVerificationSuccess() public deploySvmSmartAccount {
        // Prepare calldata for target contract
        uint256 previousNonce = svmSmartAccountInstance.nonce();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.universalTxVerification // Use txBased verification
        });

        bytes32 payloadHash = svmSmartAccountInstance.getPayloadHash(payload);

        // Mock txHash verification data
        bytes memory mockTxHashData = abi.encodePacked("mock_tx_hash_data");

        // Mock the TX_BASED_VERIFIER precompile to return true
        vm.mockCall(
            svmSmartAccountInstance.TX_BASED_VERIFIER(),
            abi.encodeWithSignature(
                "verifyTxHash(string,string,bytes,bytes32,bytes)",
                svmSmartAccountInstance.universalAccount().chainNamespace,
                svmSmartAccountInstance.universalAccount().chainId,
                svmSmartAccountInstance.universalAccount().owner,
                payloadHash,
                mockTxHashData
            ),
            abi.encode(true)
        );

        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute the payload with txHash verification
        svmSmartAccountInstance.executePayload(abi.encode(payload), mockTxHashData);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, svmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    // Test executePayload with txBased verification failure
    function testExecutionWithTxVerificationFailure() public deploySvmSmartAccount {
        // Prepare calldata for target contract
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.universalTxVerification // Use txBased verification
        });

        bytes32 payloadHash = svmSmartAccountInstance.getPayloadHash(payload);

        // Mock txHash verification data
        bytes memory mockTxHashData = abi.encodePacked("mock_tx_hash_data");

        // Mock the TX_BASED_VERIFIER precompile to return false
        vm.mockCall(
            svmSmartAccountInstance.TX_BASED_VERIFIER(),
            abi.encodeWithSignature(
                "verifyTxHash(string,string,bytes,bytes32,bytes)",
                svmSmartAccountInstance.universalAccount().chainNamespace,
                svmSmartAccountInstance.universalAccount().chainId,
                svmSmartAccountInstance.universalAccount().owner,
                payloadHash,
                mockTxHashData
            ),
            abi.encode(false)
        );

        // Expect revert when txHash verification fails
        vm.expectRevert(Errors.InvalidTxHash.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), mockTxHashData);
    }

    // Test executePayload with txBased verification and empty txHash
    function testExecutionWithTxVerificationEmptyTxHash() public deploySvmSmartAccount {
        // Prepare calldata for target contract
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.universalTxVerification // Use txBased verification
        });

        // Empty txHash data
        bytes memory emptyTxHashData = new bytes(0);

        // Expect revert when txHash data is empty
        vm.expectRevert(Errors.InvalidTxHash.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), emptyTxHashData);
    }

    function testExecutionBasic() public deploySvmSmartAccount {
        uint256 previousNonce = svmSmartAccountInstance.nonce();

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute the payload
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, svmSmartAccountInstance.nonce(), "Nonce should have incremented");
    }

    function testExecuteMulticallSuccess() public deploySvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(svmSmartAccountInstance), 1 ether);

        // Prepare multiple calls
        Multicall[] memory calls = new Multicall[](2);
        calls[0] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 123)});

        calls[1] = Multicall({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 456)
        });

        // Encode with multicall prefix (0x4e2d2ff6 is keccak256("UEA_MULTICALL")[0:4])
        bytes4 selector = bytes4(keccak256("UEA_MULTICALL"));
        bytes memory callData = abi.encode(calls);
        bytes memory multicallData = abi.encodePacked(selector, callData);

        // Create the payload
        UniversalPayload memory payload = UniversalPayload({
            to: address(0), // unused in multicall mode
            value: 0.1 ether, // total value to be distributed
            data: multicallData,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Execute the payload
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both calls executed
        uint256 magic = target.getMagicNumber();
        assertEq(magic, 456, "Multicall failed: second call should set 456");
        assertEq(address(target).balance, 0.1 ether, "Target should have received 0.1 ETH");
    }

    function testExecuteMulticallFailsAndRevertsWithReason() public deploySvmSmartAccount {
        RevertingTarget revertingTarget = new RevertingTarget();
        Multicall[] memory calls = new Multicall[](2);
        calls[0] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 999)});
        calls[1] =
            Multicall({to: address(revertingTarget), value: 0, data: abi.encodeWithSignature("revertWithReason()")});

        // Encode with selector
        bytes4 selector = bytes4(keccak256("UEA_MULTICALL"));
        bytes memory callData = abi.encode(calls);
        bytes memory multicallData = abi.encodePacked(selector, callData);

        UniversalPayload memory payload = UniversalPayload({
            to: address(0),
            value: 0,
            data: multicallData,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Should bubble up revert reason from revertingTarget
        vm.expectRevert("This function always reverts with reason");
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testExecuteMulticallSuccessWithPayload() public deploySvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(svmSmartAccountInstance), 2 ether);

        // Prepare multiple calls with different values
        Multicall[] memory calls = new Multicall[](3);
        calls[0] = Multicall({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 111)
        });

        calls[1] = Multicall({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 222)
        });

        calls[2] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 333)});

        // Encode with multicall prefix
        bytes4 selector = bytes4(keccak256("UEA_MULTICALL"));
        bytes memory callData = abi.encode(calls);
        bytes memory multicallData = abi.encodePacked(selector, callData);

        // Create the payload with total value
        UniversalPayload memory payload = UniversalPayload({
            to: address(0), // unused in multicall mode
            value: 0.2 ether, // total value to be distributed
            data: multicallData,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check all calls executed
        uint256 magic = target.getMagicNumber();
        assertEq(magic, 333, "Multicall failed: last call should set 333");
        assertEq(address(target).balance, 0.2 ether, "Target should have received 0.2 ETH total");
    }

    function testExecuteMulticallSuccessWithDifferentTarget() public deploySvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(svmSmartAccountInstance), 1 ether);

        // Deploy a second target for testing
        Target target2 = new Target();

        // Prepare multiple calls to different targets
        Multicall[] memory calls = new Multicall[](2);
        calls[0] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 777)});

        calls[1] =
            Multicall({to: address(target2), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 888)});

        // Encode with multicall prefix
        bytes4 selector = bytes4(keccak256("UEA_MULTICALL"));
        bytes memory callData = abi.encode(calls);
        bytes memory multicallData = abi.encodePacked(selector, callData);

        // Create the payload
        UniversalPayload memory payload = UniversalPayload({
            to: address(0), // unused in multicall mode
            value: 0,
            data: multicallData,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both targets were called correctly
        uint256 magic1 = target.getMagicNumber();
        uint256 magic2 = target2.getMagicNumber();
        assertEq(magic1, 777, "First target should have magic number 777");
        assertEq(magic2, 888, "Second target should have magic number 888");
    }

    function testExecuteMulticallSuccessWithDifferentTargetAndPayload() public deploySvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(svmSmartAccountInstance), 2 ether);

        // Deploy a second target for testing
        Target target2 = new Target();

        // Prepare multiple calls to different targets with different values
        Multicall[] memory calls = new Multicall[](3);
        calls[0] = Multicall({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 555)
        });

        calls[1] = Multicall({
            to: address(target2),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 666)
        });

        calls[2] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 999)});

        // Encode with multicall prefix
        bytes4 selector = bytes4(keccak256("UEA_MULTICALL"));
        bytes memory callData = abi.encode(calls);
        bytes memory multicallData = abi.encodePacked(selector, callData);

        // Create the payload with total value
        UniversalPayload memory payload = UniversalPayload({
            to: address(0), // unused in multicall mode
            value: 0.2 ether, // total value to be distributed
            data: multicallData,
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both targets were called correctly and received the right amounts
        uint256 magic1 = target.getMagicNumber();
        uint256 magic2 = target2.getMagicNumber();
        assertEq(magic1, 999, "First target should have final magic number 999");
        assertEq(magic2, 666, "Second target should have magic number 666");
        assertEq(address(target).balance, 0.1 ether, "First target should have received 0.1 ETH");
        assertEq(address(target2).balance, 0.1 ether, "Second target should have received 0.1 ETH");
    }

    function testExecutionWithValue() public deploySvmSmartAccount {
        // Fund the smart account
        vm.deal(address(svmSmartAccountInstance), 1 ether);

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Execute the payload
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 999, "Magic value was not set correctly");
        assertEq(address(target).balance, 0.1 ether, "Target contract should have received 0.1 ETH");
    }

    function testExecutionWithInvalidSignature() public deploySvmSmartAccount {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to return false
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(false)
        );

        // Should revert with InvalidSVMSignature
        vm.expectRevert(Errors.InvalidSVMSignature.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testExecutionWithExpiredDeadline() public deploySvmSmartAccount {
        // Create payload with deadline in the past
        vm.warp(block.timestamp + 1000); // Warp forward first
        uint256 deadline = block.timestamp - 100; // Now set deadline in the past

        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Should revert with ExpiredDeadline
        vm.expectRevert(Errors.ExpiredDeadline.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testReceiveFunction() public {
        // Deploy a new implementation
        UEA_SVM newUEA = new UEA_SVM();

        // Initialize it
        UniversalAccountId memory _id =
            UniversalAccountId({chainNamespace: "solana", chainId: "101", owner: ownerBytes});
        newUEA.initialize(_id);

        // Check initial balance
        assertEq(address(newUEA).balance, 0, "Initial balance should be 0");

        // Send ETH to the contract
        vm.deal(address(this), 1 ether);
        (bool success,) = address(newUEA).call{value: 0.5 ether}("");

        // Verify ETH was received
        assertTrue(success, "ETH transfer should succeed");
        assertEq(address(newUEA).balance, 0.5 ether, "Contract should have received 0.5 ETH");
    }

    // =========================================================================
    // Migration Tests
    // =========================================================================

    function test_RevertWhen_InvalidSignatureOnMigration() public deploySvmSmartAccount {
        // prepare migration payload
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp + 1000});

        // Compute payload hash
        bytes32 payloadHash = svmSmartAccountInstance.getMigrationPayloadHash(payload);

        // Sign with owner key
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to return false
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, payloadHash, signature),
            abi.encode(false)
        );

        vm.expectRevert(Errors.InvalidSVMSignature.selector);
        svmSmartAccountInstance.migrateUEA(payload, signature);
    }

    function test_RevertWhen_ExpiredDeadlineOnMigration() public deploySvmSmartAccount {
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp});

        // Compute payload hash
        bytes32 payloadHash = svmSmartAccountInstance.getMigrationPayloadHash(payload);

        // skip so deadline is expired
        skip(2);

        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to return false
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, payloadHash, signature),
            abi.encode(false)
        );

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        svmSmartAccountInstance.migrateUEA(payload, signature);
    }

    function test_SuccessfulMigrationUpdatesImplementation() public deploySvmSmartAccount {
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp + 1000});

        // Compute payload hash
        bytes32 payloadHash = svmSmartAccountInstance.getMigrationPayloadHash(payload);

        // Sign with owner key
        // bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification to return false
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, payloadHash, signature),
            abi.encode(true)
        );

        // Call migrateUEA
        svmSmartAccountInstance.migrateUEA(payload, signature);

        // Verify proxy’s storage slot now updated
        bytes32 slot = UEA_LOGIC_SLOT;
        bytes32 raw = vm.load(address(svmSmartAccountInstance), slot);
        address newImpl = address(uint160(uint256(raw)));

        assertEq(newImpl, migration.UEA_SVM_IMPLEMENTATION(), "Migration should update implementation");
    }

    // =========================================================================
    // Getter Functions Tests
    // =========================================================================

    function testDomainSeparator() public deploySvmSmartAccount {
        bytes32 domainSep = svmSmartAccountInstance.domainSeparator();

        // Calculate expected domain separator
        bytes32 expectedDomainSep = keccak256(
            abi.encode(
                svmSmartAccountInstance.DOMAIN_SEPARATOR_TYPEHASH_SVM(),
                keccak256(bytes(svmSmartAccountInstance.VERSION())),
                "101",
                address(svmSmartAccountInstance)
            )
        );

        assertEq(domainSep, expectedDomainSep, "Domain separator calculation should match");
    }

    function testDomainSeparatorTypeSVMHash() public deploySvmSmartAccount {
        // This test verifies that the DOMAIN_SEPARATOR_TYPEHASH_SVM constant matches the expected hash
        // If the EIP712Domain_SVM struct definition changes, this test will fail

        bytes32 expectedHash = keccak256("EIP712Domain_SVM(string version,string chainId,address verifyingContract)");

        // Access the constant from the deployed instance
        bytes32 actualHash = svmSmartAccountInstance.DOMAIN_SEPARATOR_TYPEHASH_SVM();

        assertEq(expectedHash, actualHash, "DOMAIN_SEPARATOR_TYPEHASH_SVM does not match expected value");
    }

    function testgetPayloadHash() public deploySvmSmartAccount {
        // Create a payload
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

        // Get the transaction hash directly
        bytes32 directHash = svmSmartAccountInstance.getPayloadHash(payload);

        // Calculate the hash manually
        bytes32 structHash = keccak256(
            abi.encode(
                UNIVERSAL_PAYLOAD_TYPEHASH,
                payload.to,
                payload.value,
                keccak256(payload.data),
                payload.gasLimit,
                payload.maxFeePerGas,
                payload.maxPriorityFeePerGas,
                svmSmartAccountInstance.nonce(),
                payload.deadline,
                uint8(payload.vType)
            )
        );

        bytes32 domainSep = svmSmartAccountInstance.domainSeparator();
        bytes32 manualHash = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));

        // Compare the hashes
        assertEq(directHash, manualHash, "Transaction hash calculation should match");
    }

    function testgetPayloadHashWithExpiredDeadline() public deploySvmSmartAccount {
        // Create a payload with deadline in the future
        uint256 deadline = block.timestamp + 100;
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        // Warp to after the deadline
        vm.warp(deadline + 1);

        // Should revert when trying to get transaction hash with expired deadline
        vm.expectRevert(Errors.ExpiredDeadline.selector);
        svmSmartAccountInstance.getPayloadHash(payload);
    }

    function testUniversalPayloadTypeHash() public pure {
        // This test verifies that the UNIVERSAL_PAYLOAD_TYPEHASH constant matches the expected hash
        // If the UniversalPayload struct definition changes, this test will fail

        bytes32 expectedHash = keccak256(
            "UniversalPayload(address to,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline,uint8 vType)"
        );

        // Access the actual hash from the imported constant
        bytes32 actualHash = UNIVERSAL_PAYLOAD_TYPEHASH;

        assertEq(expectedHash, actualHash, "UNIVERSAL_PAYLOAD_TYPEHASH does not match expected value");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    // Helper function for UniversalPayload hash
    function getCrosschainTxhash(UEA_SVM _smartAccountInstance, UniversalPayload memory payload)
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

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = _smartAccountInstance.domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    // Add a test for execution that fails with a revert reason
    function testExecutionFailureWithRevertReason() public deploySvmSmartAccount {
        // Deploy a contract that will revert with a reason
        RevertingTarget revertTarget = new RevertingTarget();

        UniversalPayload memory payload = UniversalPayload({
            to: address(revertTarget),
            value: 0,
            data: abi.encodeWithSignature("revertWithReason()"),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Should revert with the target's revert reason
        vm.expectRevert("This function always reverts with reason");
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    // Add a test for execution that fails without a revert reason
    function testExecutionFailureWithoutRevertReason() public deploySvmSmartAccount {
        // Deploy a contract that will revert without a reason
        SilentRevertingTarget silentRevertTarget = new SilentRevertingTarget();

        UniversalPayload memory payload = UniversalPayload({
            to: address(silentRevertTarget),
            value: 0,
            data: abi.encodeWithSignature("revertSilently()"),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Should revert with ExecutionFailed error
        vm.expectRevert(Errors.ExecutionFailed.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    // Add a test for execution with empty calldata
    function testExecutionWithEmptyCalldata() public deploySvmSmartAccount {
        // Create payload with empty calldata
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: "", // Empty calldata
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0,
            vType: VerificationType.signedVerification
        });

        bytes32 txHash = getCrosschainTxhash(svmSmartAccountInstance, payload);
        bytes memory signature =
            hex"16d760987b403d7a27fd095375f2a1275c0734701ad248c3bf9bc8f69456d626c37b9ee1c13da511c71d9ed0f90789327f2c40f3e59e360f7c832b6b0d818d03";

        // Mock the verification for this specific hash
        vm.mockCall(
            VERIFIER_PRECOMPILE,
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)", ownerBytes, txHash, signature),
            abi.encode(true)
        );

        // Expect the ExecutionFailed error when sending empty calldata
        vm.expectRevert(Errors.ExecutionFailed.selector);
        svmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }
}

// Helper contracts for testing reverts
contract RevertingTarget {
    function revertWithReason() external pure {
        revert("This function always reverts with reason");
    }
}

contract SilentRevertingTarget {
    function revertSilently() external pure {
        assembly {
            revert(0, 0)
        }
    }
}
