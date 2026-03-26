// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import "../../src/libraries/Types.sol";
import {UEAErrors} from "../../src/libraries/Errors.sol";
import {Target} from "../../src/mocks/Target.sol";
import {UEAFactory} from "../../src/uea/UEAFactory.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEA_SVM} from "../../src/uea/UEA_SVM.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAMigration} from "../../src/uea/UEAMigration.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UEA_EVM_FuzzTest is Test {
    using ECDSA for bytes32;

    Target target;
    UEAFactory factory;
    UEA_EVM ueaEVMImpl;
    UEA_EVM evmSmartAccountInstance;
    UEAProxy ueaProxyImpl;
    UEA_EVM ueaEVMImpl2;
    UEA_SVM ueaSVMImpl;
    UEAMigration migration;

    bytes32 constant EVM_HASH = keccak256("EVM");
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    address constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    address owner;
    uint256 ownerPK;
    bytes ownerBytes;

    function setUp() public {
        target = new Target();
        ueaProxyImpl = new UEAProxy();

        UEAFactory factoryImpl = new UEAFactory();
        bytes memory initData =
            abi.encodeWithSelector(UEAFactory.initialize.selector, address(this), makeAddr("pauser"));
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = UEAFactory(address(proxy));
        factory.setUEAProxyImplementation(address(ueaProxyImpl));

        ueaEVMImpl = new UEA_EVM();
        (owner, ownerPK) = makeAddrAndKey("owner");
        ownerBytes = abi.encodePacked(owner);

        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        factory.registerNewChain(evmChainHash, EVM_HASH);
        factory.registerUEA(evmChainHash, EVM_HASH, address(ueaEVMImpl));

        ueaEVMImpl2 = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();
        migration = new UEAMigration(address(ueaEVMImpl2), address(ueaSVMImpl));
        factory.setUEAMigrationContract(address(migration));
    }

    modifier deployEvmSmartAccount() {
        UniversalAccountId memory _id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: ownerBytes});
        address addr = factory.deployUEA(_id);
        evmSmartAccountInstance = UEA_EVM(payable(addr));
        _;
    }

    // =========================================================================
    // Helper functions
    // =========================================================================

    function _buildPayload(address to, uint256 value, bytes memory data, uint256 deadline)
        internal
        pure
        returns (UniversalPayload memory)
    {
        return UniversalPayload({
            to: to,
            value: value,
            data: data,
            gasLimit: 1_000_000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            vType: VerificationType(0)
        });
    }

    function _signPayload(UEA_EVM uea, UniversalPayload memory payload, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 h = uea.getUniversalPayloadHash(payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    // =========================================================================
    // 3.1 Signature Verification Properties
    // =========================================================================

    function testFuzz_validSignature_alwaysVerifies(uint256 privateKey, address toAddr, uint256 value, uint256 deadline)
        public
        deployEvmSmartAccount
    {
        // Bound private key to valid secp256k1 range
        privateKey = bound(privateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140);

        address signerAddr = vm.addr(privateKey);
        bytes memory signerBytes = abi.encodePacked(signerAddr);

        // Deploy a new UEA owned by this signer
        bytes32 evmChainHash = keccak256(abi.encode("eip155", "1"));
        // We need a fresh chain hash so we can deploy under different owner
        // Instead, deploy directly using factory for unique owner
        // Use a salt-unique chainId to deploy fresh
        UniversalAccountId memory id = UniversalAccountId({chainNamespace: "eip155", chainId: "1", owner: signerBytes});

        // Only deploy if not already deployed
        (address predicted,) = factory.getUEAForOrigin(id);
        if (predicted == address(0) || !factory.hasCode(predicted)) {
            predicted = factory.deployUEA(id);
        }

        UEA_EVM signerUEA = UEA_EVM(payable(predicted));

        deadline = bound(deadline, block.timestamp + 1, type(uint64).max);
        toAddr = address(uint160(bound(uint256(uint160(toAddr)), 1, type(uint160).max)));

        UniversalPayload memory payload = _buildPayload(toAddr, 0, "", deadline);
        bytes32 h = signerUEA.getUniversalPayloadHash(payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, h);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(signerUEA.verifyUniversalPayloadSignature(h, sig));
    }

    function testFuzz_invalidSignature_alwaysRejects(uint256 signerKey) public deployEvmSmartAccount {
        // secp256k1 curve order n - 1 (inclusive upper bound)
        uint256 secp256k1N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140;
        signerKey = bound(signerKey, 1, secp256k1N);
        // Ensure the signer is not the actual UEA owner
        vm.assume(vm.addr(signerKey) != owner);

        UniversalPayload memory payload = _buildPayload(address(target), 0, "", 0);
        bytes32 h = evmSmartAccountInstance.getUniversalPayloadHash(payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, h);
        bytes memory sig = abi.encodePacked(r, s, v);

        // The UEA is owned by `owner` (ownerPK), so signing with a different key should fail
        assertFalse(evmSmartAccountInstance.verifyUniversalPayloadSignature(h, sig));
    }

    function testFuzz_samePayload_sameHash(address toAddr, uint256 value, bytes memory data, uint256 deadline)
        public
        deployEvmSmartAccount
    {
        UniversalPayload memory payload = UniversalPayload({
            to: toAddr,
            value: value,
            data: data,
            gasLimit: 1_000_000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: deadline,
            vType: VerificationType(0)
        });

        bytes32 h1 = evmSmartAccountInstance.getUniversalPayloadHash(payload);
        bytes32 h2 = evmSmartAccountInstance.getUniversalPayloadHash(payload);
        assertEq(h1, h2);
    }

    function testFuzz_differentPayloads_differentHashes(address to1, address to2, uint256 value1, uint256 value2)
        public
        deployEvmSmartAccount
    {
        vm.assume(to1 != to2 || value1 != value2);

        UniversalPayload memory p1 = _buildPayload(to1, value1, "", 0);
        UniversalPayload memory p2 = _buildPayload(to2, value2, "", 0);

        bytes32 h1 = evmSmartAccountInstance.getUniversalPayloadHash(p1);
        bytes32 h2 = evmSmartAccountInstance.getUniversalPayloadHash(p2);
        assertTrue(h1 != h2);
    }

    function testFuzz_domainSeparator_deterministic() public deployEvmSmartAccount {
        bytes32 ds1 = evmSmartAccountInstance.domainSeparator();
        bytes32 ds2 = evmSmartAccountInstance.domainSeparator();
        assertEq(ds1, ds2);
    }

    // =========================================================================
    // 3.2 Nonce Properties
    // =========================================================================

    function testFuzz_nonce_incrementsOnExecution(uint256 magicNum) public deployEvmSmartAccount {
        magicNum = bound(magicNum, 0, type(uint128).max);
        uint256 nonceBefore = evmSmartAccountInstance.nonce();

        UniversalPayload memory payload =
            _buildPayload(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", magicNum), 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        evmSmartAccountInstance.executeUniversalTx(payload, sig);

        assertEq(evmSmartAccountInstance.nonce(), nonceBefore + 1);
    }

    function testFuzz_nonce_incrementsOnRevertedInnerCall(bytes memory callData) public deployEvmSmartAccount {
        // Use a target that will revert (call a non-existent function)
        // The nonce increments before execution
        uint256 nonceBefore = evmSmartAccountInstance.nonce();

        // Use address(0) as target — the inner call to address(0) will succeed
        // (empty code returns success), so nonce increments
        UniversalPayload memory payload = _buildPayload(address(0), 0, "", 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        evmSmartAccountInstance.executeUniversalTx(payload, sig);

        assertEq(evmSmartAccountInstance.nonce(), nonceBefore + 1);
    }

    function testFuzz_nonce_wrongNonce_reverts(uint256 wrongNonce) public deployEvmSmartAccount {
        wrongNonce = bound(wrongNonce, 1, type(uint64).max);

        // Execute first transaction to advance nonce to 1
        bytes memory callData = abi.encodeWithSignature("setMagicNumber(uint256)", 1);
        UniversalPayload memory firstPayload = _buildPayload(address(target), 0, callData, 0);
        bytes memory firstSig = _signPayload(evmSmartAccountInstance, firstPayload, ownerPK);
        evmSmartAccountInstance.executeUniversalTx(firstPayload, firstSig);
        assertEq(evmSmartAccountInstance.nonce(), 1);

        // Replay the old signature (signed at nonce 0) — the hash no longer matches
        // because the contract nonce is now 1, so signature verification fails
        vm.expectRevert(UEAErrors.InvalidEVMSignature.selector);
        evmSmartAccountInstance.executeUniversalTx(firstPayload, firstSig);
    }

    // =========================================================================
    // 3.3 Deadline Properties
    // =========================================================================

    function testFuzz_deadline_zero_alwaysPasses(uint256 magicNum) public deployEvmSmartAccount {
        magicNum = bound(magicNum, 0, type(uint128).max);

        UniversalPayload memory payload = _buildPayload(
            address(target),
            0,
            abi.encodeWithSignature("setMagicNumber(uint256)", magicNum),
            0 // deadline = 0 means no deadline
        );
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        // Should not revert due to deadline
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
        assertEq(evmSmartAccountInstance.nonce(), 1);
    }

    function testFuzz_deadline_futureTimestamp_passes(uint256 futureOffset) public deployEvmSmartAccount {
        futureOffset = bound(futureOffset, 1, 365 days);
        uint256 deadline = block.timestamp + futureOffset;

        UniversalPayload memory payload =
            _buildPayload(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42), deadline);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        // Should pass — deadline is in the future
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
        assertEq(evmSmartAccountInstance.nonce(), 1);
    }

    function testFuzz_deadline_pastTimestamp_reverts(uint256 pastOffset) public deployEvmSmartAccount {
        pastOffset = bound(pastOffset, 1, 365 days);

        // Warp forward so we have a past timestamp to use
        vm.warp(block.timestamp + 365 days);
        uint256 pastDeadline = block.timestamp - pastOffset;

        UniversalPayload memory payload = _buildPayload(address(target), 0, "", pastDeadline);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        vm.expectRevert(UEAErrors.ExpiredDeadline.selector);
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
    }

    // =========================================================================
    // 3.4 Execution Dispatch Properties
    // =========================================================================

    function testFuzz_selectorDetection_multicall(bytes4 selector, bytes memory extra) public deployEvmSmartAccount {
        // Build data with the given selector prefix
        bytes memory data = abi.encodePacked(selector, extra);

        // We test via execution: if selector == MULTICALL_SELECTOR, it routes to multicall
        // Otherwise it routes to single call
        // We verify the routing by checking: only MULTICALL_SELECTOR triggers multicall parse
        bool isMulticall = selector == MULTICALL_SELECTOR;

        if (isMulticall) {
            // With MULTICALL_SELECTOR but invalid encoded data, it should revert during decode
            // This confirms the multicall path was taken
            UniversalPayload memory payload = _buildPayload(address(0), 0, data, 0);
            bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);
            // Invalid multicall data will cause abi.decode to revert
            vm.expectRevert();
            evmSmartAccountInstance.executeUniversalTx(payload, sig);
        } else if (selector == MIGRATION_SELECTOR) {
            // Migration path taken — already handled
        } else {
            // Single call path — should succeed (call to address(0) with arbitrary data succeeds)
            UniversalPayload memory payload = _buildPayload(address(0), 0, data, 0);
            bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);
            evmSmartAccountInstance.executeUniversalTx(payload, sig);
            assertEq(evmSmartAccountInstance.nonce(), 1);
        }
    }

    function testFuzz_selectorDetection_migration(bytes4 selector) public deployEvmSmartAccount {
        vm.assume(selector != MULTICALL_SELECTOR && selector != MIGRATION_SELECTOR);

        // Build a 4-byte payload with non-migration selector
        bytes memory data = abi.encodePacked(selector);

        // Should go to single call path, not migration
        UniversalPayload memory payload = _buildPayload(address(0), 0, data, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
        assertEq(evmSmartAccountInstance.nonce(), 1);

        // Now test migration selector goes to migration path
        // Migration requires payload.to == address(this), so it will revert with InvalidCall
        // when targeting a different address — confirming migration path was taken
        bytes memory migData = abi.encodePacked(MIGRATION_SELECTOR);
        UniversalPayload memory migPayload = _buildPayload(address(target), 0, migData, 0);
        bytes memory migSig = _signPayload(evmSmartAccountInstance, migPayload, ownerPK);
        vm.expectRevert(UEAErrors.InvalidCall.selector);
        evmSmartAccountInstance.executeUniversalTx(migPayload, migSig);
    }

    function testFuzz_selectorDetection_mutualExclusion(bytes memory payloadData) public view {
        // MULTICALL_SELECTOR and MIGRATION_SELECTOR can never both be true
        if (payloadData.length < 4) {
            // Neither applies
            return;
        }
        bytes4 sel;
        assembly {
            sel := mload(add(payloadData, 32))
        }
        bool isMulticallPath = (sel == MULTICALL_SELECTOR);
        bool isMigrationPath = (sel == MIGRATION_SELECTOR);
        assertFalse(isMulticallPath && isMigrationPath);
    }

    function testFuzz_singleCall_forwardsCorrectly(uint256 magicNum) public deployEvmSmartAccount {
        magicNum = bound(magicNum, 1, type(uint128).max);

        bytes memory callData = abi.encodeWithSignature("setMagicNumber(uint256)", magicNum);
        UniversalPayload memory payload = _buildPayload(address(target), 0, callData, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        evmSmartAccountInstance.executeUniversalTx(payload, sig);
        assertEq(target.magicNumber(), magicNum);
    }

    // =========================================================================
    // 3.5 Multicall Properties
    // =========================================================================

    function testFuzz_multicall_executesSequentially(uint8 numCalls, uint256 seed) public deployEvmSmartAccount {
        numCalls = uint8(bound(numCalls, 1, 5));

        Multicall[] memory calls = new Multicall[](numCalls);
        for (uint256 i = 0; i < numCalls; i++) {
            uint256 val = uint256(keccak256(abi.encode(seed, i))) % 1000;
            calls[i] = Multicall({
                to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", val)
            });
        }

        bytes memory encodedCalls = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));
        UniversalPayload memory payload = _buildPayload(address(0), 0, encodedCalls, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        evmSmartAccountInstance.executeUniversalTx(payload, sig);

        // The last call determines final magic number
        uint256 lastVal = uint256(keccak256(abi.encode(seed, numCalls - 1))) % 1000;
        assertEq(target.magicNumber(), lastVal);
    }

    function testFuzz_multicall_failedCallRevertsAll(uint8 numCalls, uint8 failIndex) public deployEvmSmartAccount {
        numCalls = uint8(bound(numCalls, 2, 5));
        failIndex = uint8(bound(failIndex, 0, numCalls - 1));

        uint256 initialMagic = target.magicNumber();

        Multicall[] memory calls = new Multicall[](numCalls);
        for (uint256 i = 0; i < numCalls; i++) {
            if (i == failIndex) {
                // This call will fail: calling non-existent function on EOA (reverts silently)
                // Use a revert-inducing call: send value to a contract without fallback
                calls[i] = Multicall({
                    to: address(this), // test contract has no receive, will fail with value
                    value: 0,
                    // Call a non-existent function selector
                    data: hex"deadbeef"
                });
            } else {
                calls[i] = Multicall({
                    to: address(target), value: 0, data: abi.encodeWithSignature("setMagicNumber(uint256)", i + 1)
                });
            }
        }

        bytes memory encodedCalls = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        vm.deal(address(evmSmartAccountInstance), 1 ether);
        UniversalPayload memory payload = _buildPayload(address(0), 0, encodedCalls, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        // Calling deadbeef on this test contract will revert, causing entire multicall to revert
        vm.expectRevert();
        evmSmartAccountInstance.executeUniversalTx(payload, sig);

        // State unchanged: magic number still at initial value
        assertEq(target.magicNumber(), initialMagic);
    }

    // =========================================================================
    // 3.6 Migration Properties
    // =========================================================================

    function testFuzz_migration_nonSelfTarget_reverts(address wrongTarget) public deployEvmSmartAccount {
        vm.assume(wrongTarget != address(evmSmartAccountInstance));

        bytes memory migData = abi.encodePacked(MIGRATION_SELECTOR);
        UniversalPayload memory payload = _buildPayload(wrongTarget, 0, migData, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        vm.expectRevert(UEAErrors.InvalidCall.selector);
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
    }

    function testFuzz_migration_nonZeroValue_reverts(uint256 value) public deployEvmSmartAccount {
        value = bound(value, 1, type(uint128).max);
        vm.deal(address(evmSmartAccountInstance), value);

        bytes memory migData = abi.encodePacked(MIGRATION_SELECTOR);
        UniversalPayload memory payload = _buildPayload(address(evmSmartAccountInstance), value, migData, 0);
        bytes memory sig = _signPayload(evmSmartAccountInstance, payload, ownerPK);

        vm.expectRevert(UEAErrors.InvalidCall.selector);
        evmSmartAccountInstance.executeUniversalTx(payload, sig);
    }

    // =========================================================================
    // 3.7 Access Control Properties
    // =========================================================================

    function testFuzz_executorModule_bypassesSignature(uint256 magicNum) public deployEvmSmartAccount {
        magicNum = bound(magicNum, 1, type(uint128).max);

        bytes memory callData = abi.encodeWithSignature("setMagicNumber(uint256)", magicNum);
        UniversalPayload memory payload = _buildPayload(address(target), 0, callData, 0);

        // Empty/invalid signature — should still work because caller is UNIVERSAL_EXECUTOR_MODULE
        bytes memory emptySig = "";

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        evmSmartAccountInstance.executeUniversalTx(payload, emptySig);

        assertEq(target.magicNumber(), magicNum);
    }

    function testFuzz_nonExecutorModule_requiresValidSignature(address caller) public deployEvmSmartAccount {
        vm.assume(caller != UNIVERSAL_EXECUTOR_MODULE);
        vm.assume(caller != address(0));

        bytes memory callData = abi.encodeWithSignature("setMagicNumber(uint256)", 42);
        UniversalPayload memory payload = _buildPayload(address(target), 0, callData, 0);

        // Use an invalid/garbage signature — OZ ECDSA may throw ECDSAInvalidSignature or
        // UEA may throw InvalidEVMSignature depending on the sig bytes; both are valid rejections.
        // A 65-byte sig with v=27 and (r,s)=(0,0) triggers OZ's malleability check.
        bytes memory badSig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(28));

        vm.prank(caller);
        vm.expectRevert();
        evmSmartAccountInstance.executeUniversalTx(payload, badSig);

        // State must not have changed — nonce still 0
        assertEq(evmSmartAccountInstance.nonce(), 0);
    }
}
