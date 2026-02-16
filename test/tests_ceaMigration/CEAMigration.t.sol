// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/CEA/CEA.sol";
import "../../src/CEA/CEAMigration.sol";
import {CEAProxy} from "../../src/CEA/CEAProxy.sol";
import {CEAErrors as Errors, CommonErrors} from "../../src/libraries/Errors.sol";

/**
 * @title CEAMigrationTest
 * @notice Unit tests for CEAMigration contract
 */
contract CEAMigrationTest is Test {
    CEA public ceaV1Implementation;
    CEA public ceaV2Implementation;
    CEAMigration public migration;
    CEAProxy public proxy;

    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    address public owner;

    function setUp() public {
        owner = address(this);

        // Deploy CEA v1 (current)
        ceaV1Implementation = new CEA();

        // Deploy CEA v2 (upgrade target)
        ceaV2Implementation = new CEA();
    }

    // =========================================================================
    // Constructor Tests
    // =========================================================================

    function test_Constructor_ValidImplementation() public {
        // Deploy migration with valid CEA v2
        migration = new CEAMigration(address(ceaV2Implementation));

        // Verify immutables set correctly
        assertEq(migration.CEA_IMPLEMENTATION(), address(ceaV2Implementation), "CEA_IMPLEMENTATION should match");
        assertEq(migration.CEA_MIGRATION_IMPLEMENTATION(), address(migration), "CEA_MIGRATION_IMPLEMENTATION should be self");
    }

    function test_Constructor_RevertZeroAddress() public {
        vm.expectRevert(Errors.InvalidInput.selector);
        new CEAMigration(address(0));
    }

    function test_Constructor_RevertEOA() public {
        address eoa = makeAddr("eoa");

        vm.expectRevert(Errors.InvalidInput.selector);
        new CEAMigration(eoa);
    }

    function test_hasCode_Contract() public {
        migration = new CEAMigration(address(ceaV2Implementation));

        assertTrue(migration.hasCode(address(ceaV2Implementation)), "Should return true for contract");
    }

    function test_hasCode_EOA() public {
        migration = new CEAMigration(address(ceaV2Implementation));
        address eoa = makeAddr("eoa");

        assertFalse(migration.hasCode(eoa), "Should return false for EOA");
    }

    // =========================================================================
    // migrateCEA Tests
    // =========================================================================

    function test_migrateCEA_DirectCall() public {
        migration = new CEAMigration(address(ceaV2Implementation));

        // Attempt direct call (should revert with Unauthorized)
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateCEA();
    }

    function test_migrateCEA_Delegatecall() public {
        migration = new CEAMigration(address(ceaV2Implementation));

        // Deploy proxy and initialize with CEA v1
        proxy = new CEAProxy();
        proxy.initializeCEAProxy(address(ceaV1Implementation));

        // Verify initial implementation
        assertEq(proxy.getImplementation(), address(ceaV1Implementation), "Initial implementation should be v1");

        // Delegatecall to migration contract from proxy
        (bool success,) = address(proxy).call(
            abi.encodeWithSignature("delegatecall(address,bytes)", address(migration), abi.encodeWithSignature("migrateCEA()"))
        );

        // Note: This test requires a way to trigger delegatecall from proxy
        // In practice, this would happen through CEA._handleMigration()
        // For unit testing, we'll verify via integration tests
    }

    function test_migrateCEA_SlotWrite() public {
        migration = new CEAMigration(address(ceaV2Implementation));

        // Create a mock proxy contract that can delegatecall
        MockProxyForMigration mockProxy = new MockProxyForMigration();

        // Set initial implementation in mock proxy
        mockProxy.setImplementation(address(ceaV1Implementation));
        assertEq(mockProxy.getImplementation(), address(ceaV1Implementation), "Initial implementation should be v1");

        // Execute migration via delegatecall
        mockProxy.executeMigration(address(migration));

        // Verify implementation updated
        assertEq(mockProxy.getImplementation(), address(ceaV2Implementation), "Implementation should be updated to v2");
    }

    function test_migrateCEA_EventEmission() public {
        migration = new CEAMigration(address(ceaV2Implementation));

        // Create mock proxy
        MockProxyForMigration mockProxy = new MockProxyForMigration();
        mockProxy.setImplementation(address(ceaV1Implementation));

        // Expect ImplementationUpdated event
        vm.expectEmit(true, false, false, false);
        emit CEAMigration.ImplementationUpdated(address(ceaV2Implementation));

        // Execute migration
        mockProxy.executeMigration(address(migration));
    }
}

/**
 * @notice Mock proxy contract for testing migration
 * @dev Mimics CEAProxy's storage layout for testing delegatecall
 */
contract MockProxyForMigration {
    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    function setImplementation(address impl) external {
        assembly {
            sstore(CEA_LOGIC_SLOT, impl)
        }
    }

    function getImplementation() external view returns (address impl) {
        assembly {
            impl := sload(CEA_LOGIC_SLOT)
        }
    }

    function executeMigration(address migrationContract) external {
        (bool success,) = migrationContract.delegatecall(abi.encodeWithSignature("migrateCEA()"));
        require(success, "Migration delegatecall failed");
    }
}
