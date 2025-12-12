// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/libraries/Types.sol";
import {Target} from "../../src/mocks/Target.sol";
import {UEAFactoryV1} from "../../src/uea/UEAFactoryV1.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEA_SVM} from "../../src/uea/UEA_SVM.sol";
import {UEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAMigration} from "../../src/uea/UEAMigration.sol";

contract UEA_EVMTest is Test {
    Target target;
    UEAFactoryV1 factory;
    UEA_EVM ueaEVMImpl;
    UEA_EVM evmSmartAccountInstance;
    UEAProxy ueaProxyImpl;
    UEA_EVM ueaEVMImpl2;
    UEA_SVM ueaSVMImpl;
    UEAMigration migration;

    // VM Hash constants
    bytes32 constant EVM_HASH = keccak256("EVM");

    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    // Set up the test environment - EVM
    address owner;
    uint256 ownerPK;
    bytes ownerBytes;

    // Contract that reverts with reason string
    RevertingTarget revertingTarget;
    // Contract that reverts without reason
    SilentRevertingTarget silentRevertingTarget;

    function setUp() public {
        target = new Target();
        revertingTarget = new RevertingTarget();
        silentRevertingTarget = new SilentRevertingTarget();
        ueaEVMImpl = new UEA_EVM();

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

        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        // Register EVM chain and implementation
        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));

        // Deploy UEAMigration with both impls
        ueaEVMImpl2 = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();
        migration = new UEAMigration(address(ueaEVMImpl2), address(ueaSVMImpl));
    }

    modifier deployEvmSmartAccount() {
        UniversalAccountId memory _owner =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        address smartAccountAddress = factory.deployUEA(_owner);
        evmSmartAccountInstance = UEA_EVM(payable(smartAccountAddress));
        _;
    }

    // =========================================================================
    // Initialize and Setup Tests
    // =========================================================================

    function testInitializeFunction() public {
        // Deploy a new implementation without using the factory
        UEA_EVM newUEA = new UEA_EVM();

        // Create account ID
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

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
        UEA_EVM newUEA = new UEA_EVM();

        // Create account ID
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});

        // Initialize the account
        newUEA.initialize(_id);

        // Try to initialize again with the same ID
        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        newUEA.initialize(_id);

        // Try to initialize again with a different ID
        bytes memory differentOwnerBytes = abi.encodePacked(makeAddr("differentowner"));
        UniversalAccountId memory differentId =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: differentOwnerBytes});

        vm.expectRevert(Errors.AccountAlreadyExists.selector);
        newUEA.initialize(differentId);
    }

    function testUEAImplementation() public view {
        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        assertEq(address(factory.getUEA(evmChainHash)), address(ueaEVMImpl));
    }

    function testDeploymentCreate2() public deployEvmSmartAccount {
        UniversalAccountId memory _owner =
            UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});
        bytes32 salt = factory.generateSalt(_owner);
        assertEq(address(evmSmartAccountInstance), address(factory.UOA_to_UEA(salt)));
        assertEq(address(evmSmartAccountInstance), address(factory.computeUEA(_owner)));
    }

    function testVersionConstant() public {
        // Deploy a new implementation
        UEA_EVM newUEA = new UEA_EVM();

        // Check the version constant
        assertEq(newUEA.VERSION(), "1.0.0", "VERSION constant should be 1.0.0");
    }

    // =========================================================================
    // Public Functions Tests (User-facing functions)
    // =========================================================================

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
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);

        // Sign the payload
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute the payload
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 786, "Magic value was not set correctly");
        assertEq(previousNonce + 1, evmSmartAccountInstance.nonce(), "Nonce should have incremented");
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
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 999, "Magic value was not set correctly");
        assertEq(address(target).balance, 0.1 ether, "Target contract should have received 0.1 ETH");
    }

    function testExecutionWithZeroDeadline() public deployEvmSmartAccount {
        // Prepare calldata with zero deadline
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 555),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: 0, // Zero deadline - should not check timestamp
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload - should work even if we warp far into the future
        vm.warp(block.timestamp + 1000000);
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state changes
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 555, "Magic value was not set correctly");
    }

    function testExecutionWithEmptyData() public deployEvmSmartAccount {
        // Fund the smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        // Create a simple EOA to receive ETH
        address payable recipient = payable(makeAddr("recipient"));
        uint256 initialBalance = recipient.balance;

        // Prepare calldata with empty data
        UniversalPayload memory payload = UniversalPayload({
            to: recipient, // Send to EOA instead of target contract
            value: 0.05 ether,
            data: "", // Empty data
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify ETH was transferred
        assertEq(recipient.balance - initialBalance, 0.05 ether, "Recipient should have received 0.05 ETH");
    }

    function testExecutionWithRevertingTarget() public deployEvmSmartAccount {
        // Fund the smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        // Prepare calldata for reverting target
        UniversalPayload memory payload = UniversalPayload({
            to: address(revertingTarget),
            value: 0,
            data: abi.encodeWithSignature("revertWithReason()"),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload - should revert with the target's revert message
        vm.expectRevert("This function always reverts with reason");
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testExecutionWithSilentRevertingTarget() public deployEvmSmartAccount {
        // Fund the smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        // Prepare calldata for silently reverting target
        UniversalPayload memory payload = UniversalPayload({
            to: address(silentRevertingTarget),
            value: 0,
            data: abi.encodeWithSignature("revertSilently()"),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the payload - should revert with ExecutionFailed
        vm.expectRevert(Errors.ExecutionFailed.selector);
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testExecuteMulticallSuccess() public deployEvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

        // Prepare multiple calls
        Multicall[] memory calls = new Multicall[](2);
        calls[0] =
            Multicall({to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", 123)});

        calls[1] = Multicall({
            to: address(target),
            value: 0.1 ether,
            data: abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 456)
        });

        // Encode with multicall prefix (0x4e2d2ff6 is keccak256("MulticallPayload")[0:4])
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
            maxPriorityFeePerGas: 0
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both calls executed
        uint256 magic = target.getMagicNumber();
        assertEq(magic, 456, "Multicall failed: second call should set 456");
        assertEq(address(target).balance, 0.1 ether, "Target should have received 0.1 ETH");
    }

    function testExecuteMulticallFailsAndRevertsWithReason() public deployEvmSmartAccount {
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
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should bubble up revert reason from revertingTarget
        vm.expectRevert("This function always reverts with reason");
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);
    }

    function testExecuteMulticallSuccessWithPayload() public deployEvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(evmSmartAccountInstance), 2 ether);

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
            maxPriorityFeePerGas: 0
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check all calls executed
        uint256 magic = target.getMagicNumber();
        assertEq(magic, 333, "Multicall failed: last call should set 333");
        assertEq(address(target).balance, 0.2 ether, "Target should have received 0.2 ETH total");
    }

    function testExecuteMulticallSuccessWithDifferentTarget() public deployEvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(evmSmartAccountInstance), 1 ether);

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
            maxPriorityFeePerGas: 0
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both targets were called correctly
        uint256 magic1 = target.getMagicNumber();
        uint256 magic2 = target2.getMagicNumber();
        assertEq(magic1, 777, "First target should have magic number 777");
        assertEq(magic2, 888, "Second target should have magic number 888");
    }

    function testExecuteMulticallSuccessWithDifferentTargetAndPayload() public deployEvmSmartAccount {
        // Fund UEA smart account
        vm.deal(address(evmSmartAccountInstance), 2 ether);

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
            maxPriorityFeePerGas: 0
        });

        // Sign the payload
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect event
        vm.expectEmit(true, true, false, false);
        emit IUEA.PayloadExecuted(ownerBytes, 1);

        // Execute
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Check both targets were called correctly and received the right amounts
        uint256 magic1 = target.getMagicNumber();
        uint256 magic2 = target2.getMagicNumber();
        assertEq(magic1, 999, "First target should have final magic number 999");
        assertEq(magic2, 666, "Second target should have magic number 666");
        assertEq(address(target).balance, 0.1 ether, "First target should have received 0.1 ETH");
        assertEq(address(target2).balance, 0.1 ether, "Second target should have received 0.1 ETH");
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
            maxPriorityFeePerGas: 0
        });

        // Create a signature - Note: The nonce in the payload and the nonce used in getPayloadHash need to match
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
                        payload.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // The execution should fail because the account expects nonce to be 0, not 100
        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        // Verify state hasn't changed
        uint256 magicValueAfter = target.getMagicNumber();
        assertEq(magicValueAfter, 0, "Magic value should not have changed");
        assertEq(previousNonce, evmSmartAccountInstance.nonce(), "Nonce should not have changed");
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
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First execution should succeed
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

        uint256 previousNonce = evmSmartAccountInstance.nonce();

        // Try to execute with same nonce again
        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);

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
            maxPriorityFeePerGas: 0
        });

        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);
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
            maxPriorityFeePerGas: 0
        });

        // Create an invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignature.selector));
        evmSmartAccountInstance.executePayload(abi.encode(payload), invalidSignature);
    }

    function testRevertWithMalformedSignature() public deployEvmSmartAccount {
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 786),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });

        // Create a malformed signature (too short)
        bytes memory malformedSignature = abi.encodePacked(bytes16(0), bytes16(0));

        vm.expectRevert();
        evmSmartAccountInstance.executePayload(abi.encode(payload), malformedSignature);
    }

    function testReceiveFunction() public {
        // Deploy a new implementation
        UEA_EVM newUEA = new UEA_EVM();

        // Initialize it
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});
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

    function test_RevertWhen_InvalidSignatureOnMigration() public deployEvmSmartAccount {
        // prepare migration payload
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp + 1000});

        MigrationPayload memory payload2 =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp});

        // Compute payload hash
        bytes32 payloadHash = evmSmartAccountInstance.getMigrationPayloadHash(payload);

        // Sign with owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.migrateUEA(payload2, sig);
    }

    function test_RevertWhen_ExpiredDeadlineOnMigration() public deployEvmSmartAccount {
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp});

        // Compute payload hash
        bytes32 payloadHash = evmSmartAccountInstance.getMigrationPayloadHash(payload);

        // skip so deadline is expired
        skip(2);

        // Sign with owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(Errors.ExpiredDeadline.selector);
        evmSmartAccountInstance.migrateUEA(payload, sig);
    }

    function test_SuccessfulMigrationUpdatesImplementation() public deployEvmSmartAccount {
        MigrationPayload memory payload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp + 1000});

        // Compute payload hash
        bytes32 payloadHash = evmSmartAccountInstance.getMigrationPayloadHash(payload);

        // Sign with owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Call migrateUEA
        evmSmartAccountInstance.migrateUEA(payload, sig);

        // Verify proxy’s storage slot now updated
        bytes32 slot = UEA_LOGIC_SLOT;
        bytes32 raw = vm.load(address(evmSmartAccountInstance), slot);
        address newImpl = address(uint160(uint256(raw)));

        assertEq(newImpl, migration.UEA_EVM_IMPLEMENTATION(), "Migration should update implementation");
    }

    // =========================================================================
    // Getter Functions Tests (Public View Functions)
    // =========================================================================

    function testUniversalAccount() public deployEvmSmartAccount {
        UniversalAccountId memory account = evmSmartAccountInstance.universalAccount();
        assertEq(account.chainNamespace, "eip155");
        assertEq(account.owner, ownerBytes);
    }

    function testDomainSeparatorTypeHash() public deployEvmSmartAccount {
        // This test verifies that the DOMAIN_SEPARATOR_TYPEHASH constant matches the expected hash
        // If the EIP712Domain struct definition changes, this test will fail

        bytes32 expectedHash = keccak256("EIP712Domain(string version,uint256 chainId,address verifyingContract)");

        // Access the constant from the deployed instance
        bytes32 actualHash = evmSmartAccountInstance.DOMAIN_SEPARATOR_TYPEHASH();

        assertEq(expectedHash, actualHash, "DOMAIN_SEPARATOR_TYPEHASH does not match expected value");
    }

    function testUniversalPayloadTypeHash() public pure {
        // This test verifies that the UNIVERSAL_PAYLOAD_TYPEHASH constant matches the expected hash
        // If the UniversalPayload struct definition changes, this test will fail

        bytes32 expectedHash = keccak256(
            "UniversalPayload(address to,uint256 value,bytes data,uint256 gasLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 nonce,uint256 deadline)"
        );

        // Access the actual hash from the imported constant
        bytes32 actualHash = UNIVERSAL_PAYLOAD_TYPEHASH;

        assertEq(expectedHash, actualHash, "UNIVERSAL_PAYLOAD_TYPEHASH does not match expected value");
    }

    function testVerifyPayloadSignature() public deployEvmSmartAccount {
        // Create a message hash
        bytes32 messageHash = keccak256(abi.encodePacked("test message"));

        // Sign the message with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify the signature is valid
        bool isValid = evmSmartAccountInstance.verifyPayloadSignature(messageHash, signature);
        assertTrue(isValid, "Signature should be valid for the owner");

        // Test with wrong signer
        ( /*address wrongSigner*/ , uint256 wrongPK) = makeAddrAndKey("wrongSigner");
        (v, r, s) = vm.sign(wrongPK, messageHash);
        bytes memory wrongSignature = abi.encodePacked(r, s, v);

        bool isInvalid = evmSmartAccountInstance.verifyPayloadSignature(messageHash, wrongSignature);
        assertFalse(isInvalid, "Signature should be invalid for wrong signer");
    }

    // =========================================================================
    // Verify Payload TxHash Tests
    // =========================================================================
    // Note: mock calls are used to test the TX_BASED_VERIFIER precompile call.
    
    
    
    
    
    function testgetPayloadHash() public deployEvmSmartAccount {
        // Create a payload
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 123),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });

        // Get the transaction hash directly
        bytes32 directHash = evmSmartAccountInstance.getPayloadHash(payload);

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
                evmSmartAccountInstance.nonce(),
                payload.deadline
            )
        );

        bytes32 domainSep = evmSmartAccountInstance.domainSeparator();
        bytes32 manualHash = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));

        // Compare the hashes
        assertEq(directHash, manualHash, "Transaction hash calculation should match");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

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
                payload.deadline
            )
        );

        // Calculate the domain separator using EIP-712
        bytes32 _domainSeparator = _smartAccountInstance.domainSeparator();

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator, structHash));
    }

    // Tests for UEModule caller-based verification
    function testExecutePayloadAsUEModuleWithoutSignature() public deployEvmSmartAccount {
        // Fund UEA
        vm.deal(address(evmSmartAccountInstance), 1 ether);
        
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });
        
        // Prank as UE_MODULE
        vm.prank(evmSmartAccountInstance.UE_MODULE());
        evmSmartAccountInstance.executePayload(abi.encode(payload), "");
        
        // Verify execution succeeded
        assertEq(target.getMagicNumber(), 999, "Execution should succeed for UE_MODULE");
    }

    function testExecutePayloadAsUserRequiresSignature() public deployEvmSmartAccount {
        // Fund UEA
        vm.deal(address(evmSmartAccountInstance), 1 ether);
        
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });
        
        // Try to execute with wrong signer's signature as regular user
        (address wrongSigner, uint256 wrongPK) = makeAddrAndKey("wrongSigner");
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPK, txHash);
        bytes memory wrongSignature = abi.encodePacked(r, s, v);
        
        vm.expectRevert(Errors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executePayload(abi.encode(payload), wrongSignature);
    }

    function testExecutePayloadAsUserWithValidSignature() public deployEvmSmartAccount {
        // Fund UEA
        vm.deal(address(evmSmartAccountInstance), 1 ether);
        
        UniversalPayload memory payload = UniversalPayload({
            to: address(target),
            value: 0,
            data: abi.encodeWithSignature("setMagicNumber(uint256)", 999),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            nonce: 0,
            deadline: block.timestamp + 1000,
            maxPriorityFeePerGas: 0
        });
        
        bytes32 txHash = getCrosschainTxhash(evmSmartAccountInstance, payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Execute with valid signature
        evmSmartAccountInstance.executePayload(abi.encode(payload), signature);
        
        // Verify execution succeeded
        assertEq(target.getMagicNumber(), 999, "Execution should succeed with valid signature");
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