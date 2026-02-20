// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/CEA/CEA.sol";
import "../../src/CEA/CEAFactory.sol";
import {CEAProxy} from "../../src/CEA/CEAProxy.sol";
import "../../src/CEA/CEAMigration.sol";
import {CEAErrors as Errors} from "../../src/libraries/Errors.sol";
import {Multicall, MULTICALL_SELECTOR, MIGRATION_SELECTOR} from "../../src/libraries/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title CEA_MigrationTest
 * @notice Unit tests for CEA migration functionality
 */
contract CEA_MigrationTest is Test {
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    CEAMigration public migration;
    CEA public ceaInstance;

    address public owner;
    address public vault;
    address public ueaOnPush;
    address public universalGateway;

    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    function setUp() public {
        owner = address(this);
        vault = makeAddr("vault");
        ueaOnPush = makeAddr("ueaOnPush");
        universalGateway = makeAddr("universalGateway");

        // Deploy CEA v1
        ceaImplementation = new CEA();
        ceaProxyImplementation = new CEAProxy();

        // Deploy factory
        CEAFactory factoryImpl = new CEAFactory();
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            universalGateway
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));

        // Deploy CEA
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        ceaInstance = CEA(payable(ceaAddress));

        // Deploy CEA v2 and migration contract
        CEA ceaV2 = new CEA();
        migration = new CEAMigration(address(ceaV2));
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    function generateTxID(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("txID", nonce));
    }

    function generateUniversalTxID(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("universalTxID", nonce));
    }

    function buildMigrationPayload(address) internal pure returns (bytes memory) {
        return abi.encodePacked(MIGRATION_SELECTOR);
    }

    // =========================================================================
    // initializeCEA Tests
    // =========================================================================

    function test_initializeCEA_WithFactory() public {
        CEA newCEA = new CEA();

        newCEA.initializeCEA(ueaOnPush, vault, universalGateway, address(factory));

        assertTrue(newCEA.isInitialized(), "CEA should be initialized");
        assertEq(address(newCEA.factory()), address(factory), "Factory should be set");
    }

    function test_initializeCEA_ZeroFactory() public {
        CEA newCEA = new CEA();

        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, vault, universalGateway, address(0));
    }

    // =========================================================================
    // isMigration Tests (via executeUniversalTx)
    // =========================================================================

    function test_isMigration_True() public {
        // Set migration contract in factory
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Build migration payload
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        // Execute migration (will test isMigration detection internally)
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // If execution reaches here without reverting, isMigration worked
        assertTrue(true, "Migration selector detected successfully");
    }

    // =========================================================================
    // _handleMigration Validation Tests
    // =========================================================================

    function test_handleMigration_TopLevelFormat_Succeeds() public {
        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Top-level MIGRATION_SELECTOR (no Multicall wrapper)
        bytes memory payload = abi.encodePacked(MIGRATION_SELECTOR);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify implementation changed
        address implAfter = CEAProxy(payable(address(ceaInstance))).getImplementation();
        assertEq(implAfter, migration.CEA_IMPLEMENTATION(), "Implementation should be CEA v2");
    }

    function test_handleMigration_NonZeroMsgValue_Reverts() public {
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodePacked(MIGRATION_SELECTOR);

        vm.deal(vault, 1 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx{value: 1 ether}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_handleMigration_MigrationInsideMulticall_Reverts() public {
        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // MIGRATION_SELECTOR wrapped in multicall fails as generic execution failure
        // (CEA has no function matching the migration selector, so .call() reverts)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({
            to: address(ceaInstance),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR)
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_handleMigration_NoMigrationContract() public {
        // Do NOT set migration contract (remains address(0))

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Build migration payload
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        // Expect InvalidCall revert
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidCall.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // Batched Migration Tests
    // =========================================================================

    function test_handleMulticall_MigrationInBatch() public {
        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Build batched payload with migration
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = Multicall({
            to: makeAddr("external"),
            value: 0,
            data: abi.encodeWithSignature("someFunction()")
        });
        calls[1] = Multicall({
            to: address(ceaInstance),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR)  // Migration in batch!
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        // Migration selector in multicall fails as generic execution failure
        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_handleMulticall_MigrationInBatch_FirstPosition() public {
        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Build batched payload with migration in first position
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = Multicall({
            to: address(ceaInstance),
            value: 0,
            data: abi.encodePacked(MIGRATION_SELECTOR)  // Migration first!
        });
        calls[1] = Multicall({
            to: makeAddr("external"),
            value: 0,
            data: abi.encodeWithSignature("someFunction()")
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        // Migration selector in multicall fails as generic execution failure
        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // Standalone Migration Tests
    // =========================================================================

    function test_handleExecution_StandaloneMigration() public {
        // Set migration contract
        factory.setCEAMigrationContract(address(migration));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Build standalone migration payload
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        // Get initial implementation
        address implBefore = CEAProxy(payable(address(ceaInstance))).getImplementation();

        // Execute migration
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Get updated implementation
        address implAfter = CEAProxy(payable(address(ceaInstance))).getImplementation();

        // Verify implementation changed
        assertTrue(implBefore != implAfter, "Implementation should have changed");
        assertEq(implAfter, migration.CEA_IMPLEMENTATION(), "Implementation should be CEA v2");
    }
}
