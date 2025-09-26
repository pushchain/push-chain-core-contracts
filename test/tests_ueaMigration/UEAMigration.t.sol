// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./BaseTest.t.sol";

/**
 * @title   UEAMigrationTest
 * @dev     Test suite for UEAMigration contract
 */
contract UEAMigrationTest is BaseTest {
    
    SelfDestructingImplementation public selfDestructImpl;
    
    // Test proxy for delegatecall testing
    TestProxy public testProxy;
    
    function setUp() public override {
        super.setUp();
        
        // Deploy test proxy for delegatecall testing
        testProxy = new TestProxy();
    }

    function test_constructor_WithValidImplementations() public {
        // Deploy new migration contract with valid implementations
        UEAMigration newMigration = new UEAMigration(
            address(ueaEVMImplV1),
            address(ueaSVMImplV1)
        );
        
        // Verify implementations are set correctly
        assertEq(
            newMigration.UEA_EVM_IMPLEMENTATION(),
            address(ueaEVMImplV1),
            "EVM implementation not set correctly"
        );
        assertEq(
            newMigration.UEA_SVM_IMPLEMENTATION(),
            address(ueaSVMImplV1),
            "SVM implementation not set correctly"
        );
        
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
            newMigration.UEA_MIGRATION_IMPLEMENTATION(),
            address(newMigration),
            "Migration implementation mismatch"
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
        new UEAMigration(
            address(ueaEVMImplV1),
            address(ueaEVMImplV1)
        );
    }
    
    /**
     * @dev Test constructor with different valid implementations
     */
    function test_constructor_WithDifferentValidImplementations() public {
        UEAMigration newMigration = new UEAMigration(
            address(ueaEVMImplV1),
            address(ueaSVMImplV1)
        );
        
        assertTrue(
            newMigration.UEA_EVM_IMPLEMENTATION() != newMigration.UEA_SVM_IMPLEMENTATION(),
            "EVM and SVM implementations should be different"
        );
        assertEq(
            newMigration.UEA_EVM_IMPLEMENTATION(),
            address(ueaEVMImplV1),
            "EVM implementation should match input"
        );
        assertEq(
            newMigration.UEA_SVM_IMPLEMENTATION(),
            address(ueaSVMImplV1),
            "SVM implementation should match input"
        );
    }
}

// Helper contracts for testing
/**
 * @dev Self-destructing implementation for testing edge cases
 */
contract SelfDestructingImplementation {
    bool public destroyed;
    
    function version() external view returns (string memory) {
        require(!destroyed, "Contract destroyed");
        return "self-destruct";
    }
    
    function destroy() external {
        destroyed = true;
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @dev Test proxy for delegatecall testing
 */
contract TestProxy {
    // Storage slot for implementation (matches UEA_LOGIC_SLOT)
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;
    
    function setImplementation(address impl) external {
        assembly {
            sstore(UEA_LOGIC_SLOT, impl)
        }
    }
    
    function getImplementation() external view returns (address impl) {
        assembly {
            impl := sload(UEA_LOGIC_SLOT)
        }
    }
    
    function delegateTo(address target, bytes calldata data) external returns (bool success, bytes memory returnData) {
        return target.delegatecall(data);
    }
}
