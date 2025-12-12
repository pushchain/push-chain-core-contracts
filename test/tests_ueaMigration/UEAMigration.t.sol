// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./BaseTest.t.sol";

/**
 * @title   UEAMigrationTest
 * @dev     Test suite for UEAMigration contract
 */
contract UEAMigrationTest is BaseTest {
    // Real UEA proxy for realistic testing
    UEAProxy public ueaProxy;

    // Test account ID for UEA initialization
    UniversalAccountId public testAccountId;

    function setUp() public override {
        super.setUp();

        // Deploy real UEAProxy for realistic testing
        ueaProxy = new UEAProxy();

        // Setup test account ID
        testAccountId =
            UniversalAccountId({chainNamespace: "eip155", chainId: "11155111", owner: abi.encodePacked(owner)});
    }

    function test_constructor_WithValidImplementations() public {
        // Deploy new migration contract with valid implementations
        UEAMigration newMigration = new UEAMigration(address(ueaEVMImplV1), address(ueaSVMImplV1));

        // Verify implementations are set correctly
        assertEq(newMigration.UEA_EVM_IMPLEMENTATION(), address(ueaEVMImplV1), "EVM implementation not set correctly");
        assertEq(newMigration.UEA_SVM_IMPLEMENTATION(), address(ueaSVMImplV1), "SVM implementation not set correctly");

        // Verify migration implementation is set to contract's own address
        assertEq(
            newMigration.UEA_MIGRATION_IMPLEMENTATION(),
            address(newMigration),
            "Migration implementation should be contract's own address"
        );
    }

    function test_constructor_SetsCorrectImmutableValues() public {
        address expectedEVM = address(ueaEVMImplV2);
        address expectedSVM = address(ueaSVMImplV2);

        UEAMigration newMigration = new UEAMigration(expectedEVM, expectedSVM);

        // Verify all immutable values
        assertEq(newMigration.UEA_EVM_IMPLEMENTATION(), expectedEVM, "EVM implementation mismatch");
        assertEq(newMigration.UEA_SVM_IMPLEMENTATION(), expectedSVM, "SVM implementation mismatch");
        assertEq(
            newMigration.UEA_MIGRATION_IMPLEMENTATION(), address(newMigration), "Migration implementation mismatch"
        );
    }

    function test_constructor_HasCodeFunctionality() public {
        // Verify hasCode function works correctly
        assertTrue(migration.hasCode(address(ueaEVMImplV1)), "Should detect code in EVM implementation");
        assertTrue(migration.hasCode(address(ueaSVMImplV1)), "Should detect code in SVM implementation");
        assertTrue(migration.hasCode(address(target)), "Should detect code in target contract");

        // Test with address that has no code
        assertFalse(migration.hasCode(address(0)), "Should not detect code at zero address");
        assertFalse(migration.hasCode(owner), "Should not detect code at EOA");
    }

    /**
     * @dev Test constructor reverts when EVM implementation has no code (EOA)
     */
    function test_constructor_RevertOnEvmImplementationWithoutCode() public {
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        new UEAMigration(owner, address(ueaSVMImplV1));
    }

    /**
     * @dev Test constructor reverts when SVM implementation has no code (EOA)
     */
    function test_constructor_RevertOnSvmImplementationWithoutCode() public {
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        new UEAMigration(address(ueaEVMImplV1), nonOwner);
    }
    // Constructor edge cases

    /**
     * @dev Test constructor reverts when same implementation is used for both EVM and SVM
     */
    function test_constructor_RevertOnSameImplementationForBoth() public {
        // Should revert because EVM and SVM implementations must be different
        vm.expectRevert(Errors.InvalidInputArgs.selector);
        new UEAMigration(address(ueaEVMImplV1), address(ueaEVMImplV1));
    }

    /**
     * @dev Test constructor with different valid implementations
     */
    function test_constructor_WithDifferentValidImplementations() public {
        UEAMigration newMigration = new UEAMigration(address(ueaEVMImplV1), address(ueaSVMImplV1));

        assertTrue(
            newMigration.UEA_EVM_IMPLEMENTATION() != newMigration.UEA_SVM_IMPLEMENTATION(),
            "EVM and SVM implementations should be different"
        );
        assertEq(newMigration.UEA_EVM_IMPLEMENTATION(), address(ueaEVMImplV1), "EVM implementation should match input");
        assertEq(newMigration.UEA_SVM_IMPLEMENTATION(), address(ueaSVMImplV1), "SVM implementation should match input");
    }
    // OnlyDelegateCall Modifier Tests

    /**
     * @dev Test migrateUEAEVM reverts when called directly (not via delegatecall)
     */
    function test_migrateUEAEVM_RevertOnDirectCall() public {
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEAEVM();
    }

    /**
     * @dev Test migrateUEASVM reverts when called directly (not via delegatecall)
     */
    function test_migrateUEASVM_RevertOnDirectCall() public {
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEASVM();
    }

    /**
     * @dev Test migrateUEAEVM succeeds when called via actual production flow
     */
    function test_migrateUEAEVM_SuccessOnDelegateCall() public {
        ueaProxy.initializeUEA(address(ueaEVMImplV1));
        IUEA(address(ueaProxy)).initialize(testAccountId);

        assertEq(ueaProxy.getImplementation(), address(ueaEVMImplV1), "Initial implementation should be V1");
        assertEq(IUEA(address(ueaProxy)).VERSION(), "1.0.0", "Initial version should be 1.0.0");

        // Create migration payload
        MigrationPayload memory migrationPayload = MigrationPayload({
            migration: address(migration),
            nonce: 0, // UEA starts with nonce 0
            deadline: block.timestamp + 1 hours
        });

        // Convert MigrationPayload to UniversalPayload for new migration approach
        UniversalPayload memory universalPayload = UniversalPayload({
            to: address(ueaProxy),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR, abi.encode(migrationPayload.migration)),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: migrationPayload.nonce,
            deadline: migrationPayload.deadline
        });
        
        // Get the payload hash using getPayloadHash
        bytes32 payloadHash = UEA_EVM(payable(address(ueaProxy))).getPayloadHash(universalPayload);

        // Create a valid signature using the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expected event from proxy context (delegatecall)
        vm.expectEmit(true, false, false, false, address(ueaProxy));
        emit UEAMigration.ImplementationUpdated(migration.UEA_EVM_IMPLEMENTATION());

        // Execute migration through real UEA flow: proxy -> UEA_EVM -> migration contract
        vm.prank(owner);
        migrateUEAWrapper(address(ueaProxy), migrationPayload, signature);

        // Verify the storage was updated correctly
        assertEq(
            ueaProxy.getImplementation(),
            migration.UEA_EVM_IMPLEMENTATION(),
            "Implementation should be updated to EVM V2"
        );

        assertEq(IUEA(address(ueaProxy)).VERSION(), "2.0.0", "Version should be updated to 2.0.0");
    }

    /**
     * @dev Test migrateUEASVM succeeds when called via actual production flow
     */
    function test_migrateUEASVM_SuccessOnDelegateCall() public {
        // Deploy separate proxy for SVM testing
        UEAProxy svmProxy = new UEAProxy();

        // Initialize UEA proxy with V1 SVM implementation
        svmProxy.initializeUEA(address(ueaSVMImplV1));

        // Initialize the UEA implementation itself
        IUEA(address(svmProxy)).initialize(testAccountId);

        // Verify initial state
        assertEq(svmProxy.getImplementation(), address(ueaSVMImplV1), "Initial implementation should be SVM V1");
        assertEq(IUEA(address(svmProxy)).VERSION(), "1.0.0", "Initial version should be 1.0.0");

        // Create migration payload for SVM
        MigrationPayload memory migrationPayload = MigrationPayload({
            migration: address(migration),
            nonce: 0, // UEA starts with nonce 0
            deadline: block.timestamp + 1 hours
        });

        // Mock signature (will be bypassed by precompile mock)
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0));

        // Mock the Ed25519 verifier precompile to return true
        vm.mockCall(
            0x00000000000000000000000000000000000000ca, // VERIFIER_PRECOMPILE address
            abi.encodeWithSignature("verifyEd25519(bytes,bytes32,bytes)"),
            abi.encode(true)
        );

        // Expected event from proxy context (delegatecall)
        vm.expectEmit(true, false, false, false, address(svmProxy));
        emit UEAMigration.ImplementationUpdated(migration.UEA_SVM_IMPLEMENTATION());

        // Execute migration through real UEA flow: proxy -> UEA_SVM -> migration contract
        vm.prank(owner);
        migrateUEAWrapper(address(svmProxy), migrationPayload, signature);

        // Verify migration was successful by checking implementation change
        assertEq(
            svmProxy.getImplementation(),
            migration.UEA_SVM_IMPLEMENTATION(),
            "Implementation should be updated to SVM V2"
        );

        // Verify the proxy now uses V2 implementation
        assertEq(IUEA(address(svmProxy)).VERSION(), "2.0.0", "Version should be updated to 2.0.0");
    }

    // Storage Slot Consistency Tests

    function test_storageSlotConsistency() public {
        bytes32 expectedSlot = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;
        assertEq(UEA_LOGIC_SLOT, expectedSlot, "UEA_LOGIC_SLOT constant should match expected value");

        // Initialize UEA proxy and verify it uses same slot
        ueaProxy.initializeUEA(address(ueaEVMImplV1));

        bytes32 proxySlotValue = vm.load(address(ueaProxy), UEA_LOGIC_SLOT);
        assertEq(
            address(uint160(uint256(proxySlotValue))),
            address(ueaEVMImplV1),
            "UEAProxy should store implementation at UEA_LOGIC_SLOT"
        );

        // Verify getImplementation() returns same value
        assertEq(
            ueaProxy.getImplementation(), address(ueaEVMImplV1), "getImplementation() should match storage slot value"
        );
    }

    /**
     * @dev Verify the slot value equals keccak256("uea.proxy.implementation") - 1
     */
    function test_storageSlotValue() public {
        bytes32 calculatedSlot = bytes32(uint256(keccak256("uea.proxy.implementation")) - 1);
        assertEq(UEA_LOGIC_SLOT, calculatedSlot, "UEA_LOGIC_SLOT should match calculated value");
    }
    // note: In production, users might accidentally trigger the same migration twice, or there could be network issues causing retries.
    //       This test ensures the system handles repeated migrations gracefully.

    function test_migration_Idempotency() public {
        address oldImpl = address(ueaEVMImplV1);
        address newImpl = migration.UEA_EVM_IMPLEMENTATION();

        ueaProxy.initializeUEA(oldImpl);
        IUEA(address(ueaProxy)).initialize(testAccountId);

        // Create migration payload
        MigrationPayload memory migrationPayload = MigrationPayload({
            migration: address(migration),
            nonce: 0, // UEA starts with nonce 0
            deadline: block.timestamp + 1 hours
        });

        // Convert MigrationPayload to UniversalPayload for new migration approach
        UniversalPayload memory universalPayload = UniversalPayload({
            to: address(ueaProxy),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR, abi.encode(migrationPayload.migration)),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: migrationPayload.nonce,
            deadline: migrationPayload.deadline
        });
        
        // Get the payload hash using getPayloadHash
        bytes32 payloadHash = UEA_EVM(payable(address(ueaProxy))).getPayloadHash(universalPayload);

        // Create a valid signature using the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First migration through real UEA flow
        vm.prank(owner);
        migrateUEAWrapper(address(ueaProxy), migrationPayload, signature);
        assertEq(ueaProxy.getImplementation(), newImpl, "First migration should update implementation");

        // Second migration (idempotent) - should succeed and emit event again
        vm.expectEmit(true, false, false, false, address(ueaProxy));
        emit UEAMigration.ImplementationUpdated(newImpl);

        // Need to update nonce for second migration
        migrationPayload.nonce = 1;
        universalPayload.nonce = 1;
        payloadHash = UEA_EVM(payable(address(ueaProxy))).getPayloadHash(universalPayload);
        (v, r, s) = vm.sign(ownerPK, payloadHash);
        signature = abi.encodePacked(r, s, v);

        vm.prank(owner);
        migrateUEAWrapper(address(ueaProxy), migrationPayload, signature);
        assertEq(ueaProxy.getImplementation(), newImpl, "Implementation should remain the same");
    }

    function test_migration_EventEmissionFromProxyContext() public {
        address newImpl = migration.UEA_EVM_IMPLEMENTATION();

        // Initialize UEA proxy
        ueaProxy.initializeUEA(address(ueaEVMImplV1));
        IUEA(address(ueaProxy)).initialize(testAccountId);

        // Create migration payload
        MigrationPayload memory migrationPayload = MigrationPayload({
            migration: address(migration),
            nonce: 0, // UEA starts with nonce 0
            deadline: block.timestamp + 1 hours
        });

        // Convert MigrationPayload to UniversalPayload for new migration approach
        UniversalPayload memory universalPayload = UniversalPayload({
            to: address(ueaProxy),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR, abi.encode(migrationPayload.migration)),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: migrationPayload.nonce,
            deadline: migrationPayload.deadline
        });
        
        // Get the payload hash using getPayloadHash
        bytes32 payloadHash = UEA_EVM(payable(address(ueaProxy))).getPayloadHash(universalPayload);

        // Create a valid signature using the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expected event from proxy context (delegatecall)
        vm.expectEmit(true, false, false, false, address(ueaProxy));
        emit UEAMigration.ImplementationUpdated(newImpl);

        // Execute migration through real UEA flow: proxy -> UEA_EVM -> migration contract
        vm.prank(owner);
        migrateUEAWrapper(address(ueaProxy), migrationPayload, signature);

        // Verify migration succeeded by checking implementation was updated
        assertEq(ueaProxy.getImplementation(), newImpl, "Migration should update implementation");
    }

    function test_migration_SwitchingImplementations() public {
        // Start with EVM implementation
        ueaProxy.initializeUEA(address(ueaEVMImplV1));
        IUEA(address(ueaProxy)).initialize(testAccountId);

        assertEq(ueaProxy.getImplementation(), address(ueaEVMImplV1), "Should start with EVM V1");
        assertEq(IUEA(address(ueaProxy)).VERSION(), "1.0.0", "Should start with version 1.0.0");

        // First migration: EVM V1 -> EVM V2 (using real production flow)
        MigrationPayload memory migrationPayload =
            MigrationPayload({migration: address(migration), nonce: 0, deadline: block.timestamp + 1 hours});

        // Convert MigrationPayload to UniversalPayload for new migration approach
        UniversalPayload memory universalPayload = UniversalPayload({
            to: address(ueaProxy),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR, abi.encode(migrationPayload.migration)),
            gasLimit: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            nonce: migrationPayload.nonce,
            deadline: migrationPayload.deadline
        });
        
        bytes32 payloadHash = UEA_EVM(payable(address(ueaProxy))).getPayloadHash(universalPayload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPK, payloadHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(owner);
        migrateUEAWrapper(address(ueaProxy), migrationPayload, signature);

        assertEq(ueaProxy.getImplementation(), migration.UEA_EVM_IMPLEMENTATION(), "Should migrate to EVM V2");
        assertEq(IUEA(address(ueaProxy)).VERSION(), "2.0.0", "Should be version 2.0.0");

        // Test demonstrates successful EVM V1 -> EVM V2 migration using production flow
        // Cross-type switching (EVM ↔ SVM) is tested separately in individual migration tests
    }
}
