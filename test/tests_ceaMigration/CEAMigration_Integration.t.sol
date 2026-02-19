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
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockGasToken} from "../mocks/MockGasToken.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";

/**
 * @title CEAMigration_IntegrationTest
 * @notice End-to-end integration tests for CEA migration flow
 */
contract CEAMigration_IntegrationTest is Test {
    CEA public ceaV1Implementation;
    CEA public ceaV2Implementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    CEAMigration public migration;
    CEA public ceaInstance;
    MockGasToken public token;
    MockUniversalGateway public universalGateway;

    address public owner;
    address public vault;
    address public ueaOnPush;

    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    function setUp() public {
        owner = address(this);
        vault = makeAddr("vault");
        ueaOnPush = makeAddr("ueaOnPush");

        // Deploy mock contracts
        token = new MockGasToken();
        universalGateway = new MockUniversalGateway();

        // Deploy CEA v1
        ceaV1Implementation = new CEA();
        ceaProxyImplementation = new CEAProxy();

        // Deploy factory
        CEAFactory factoryImpl = new CEAFactory();
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            vault,
            address(ceaProxyImplementation),
            address(ceaV1Implementation),
            address(universalGateway)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));

        // Deploy CEA
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        ceaInstance = CEA(payable(ceaAddress));

        // Deploy CEA v2 and migration contract
        ceaV2Implementation = new CEA();
        migration = new CEAMigration(address(ceaV2Implementation));

        // Set migration contract in factory
        factory.setCEAMigrationContract(address(migration));
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

    function executeMigration() internal {
        bytes32 txID = generateTxID(999);
        bytes32 universalTxID = generateUniversalTxID(999);
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // Full Migration Flow Tests
    // =========================================================================

    function test_FullMigrationFlow() public {
        // Get initial implementation
        address implBefore = CEAProxy(payable(address(ceaInstance))).getImplementation();
        assertEq(implBefore, address(ceaV1Implementation), "Should start with v1");

        // Execute migration
        executeMigration();

        // Get updated implementation
        address implAfter = CEAProxy(payable(address(ceaInstance))).getImplementation();
        assertEq(implAfter, address(ceaV2Implementation), "Should be upgraded to v2");
    }

    // =========================================================================
    // State Persistence Tests
    // =========================================================================

    function test_StatePersistence_UEA() public {
        address ueaBefore = ceaInstance.UEA();

        executeMigration();

        address ueaAfter = ceaInstance.UEA();
        assertEq(ueaAfter, ueaBefore, "UEA should be preserved");
        assertEq(ueaAfter, ueaOnPush, "UEA should match original");
    }

    function test_StatePersistence_VAULT() public {
        address vaultBefore = ceaInstance.VAULT();

        executeMigration();

        address vaultAfter = ceaInstance.VAULT();
        assertEq(vaultAfter, vaultBefore, "VAULT should be preserved");
        assertEq(vaultAfter, vault, "VAULT should match original");
    }

    function test_StatePersistence_UNIVERSAL_GATEWAY() public {
        address gatewayBefore = ceaInstance.UNIVERSAL_GATEWAY();

        executeMigration();

        address gatewayAfter = ceaInstance.UNIVERSAL_GATEWAY();
        assertEq(gatewayAfter, gatewayBefore, "UNIVERSAL_GATEWAY should be preserved");
        assertEq(gatewayAfter, address(universalGateway), "UNIVERSAL_GATEWAY should match original");
    }

    function test_StatePersistence_isExecuted() public {
        // Execute a transaction before migration
        bytes32 txID1 = generateTxID(1);
        bytes32 universalTxID1 = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({
            to: address(this),
            value: 0,
            data: abi.encodeWithSignature("dummyFunction()")
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID1, universalTxID1, ueaOnPush, payload);

        // Verify executed
        assertTrue(ceaInstance.isExecuted(txID1), "Transaction should be marked as executed");

        // Execute migration
        executeMigration();

        // Verify isExecuted mapping preserved
        assertTrue(ceaInstance.isExecuted(txID1), "isExecuted mapping should be preserved after migration");
    }

    function test_StatePersistence_Factory() public {
        address factoryBefore = address(ceaInstance.factory());

        executeMigration();

        address factoryAfter = address(ceaInstance.factory());
        assertEq(factoryAfter, factoryBefore, "Factory reference should be preserved");
        assertEq(factoryAfter, address(factory), "Factory should match original");
    }

    // =========================================================================
    // Fund Persistence Tests
    // =========================================================================

    function test_FundPersistence_Native() public {
        // Fund CEA with native tokens
        uint256 amount = 10 ether;
        vm.deal(address(ceaInstance), amount);

        uint256 balanceBefore = address(ceaInstance).balance;
        assertEq(balanceBefore, amount, "CEA should have native balance");

        // Execute migration
        executeMigration();

        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, balanceBefore, "Native balance should be preserved");
    }

    function test_FundPersistence_ERC20() public {
        // Fund CEA with ERC20 tokens
        uint256 amount = 1000e18;
        token.mint(address(ceaInstance), amount);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));
        assertEq(balanceBefore, amount, "CEA should have ERC20 balance");

        // Execute migration
        executeMigration();

        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, balanceBefore, "ERC20 balance should be preserved");
    }

    function test_FundPersistence_MultipleTokens() public {
        // Fund with multiple tokens
        MockGasToken token1 = new MockGasToken();
        MockGasToken token2 = new MockGasToken();

        token1.mint(address(ceaInstance), 100e18);
        token2.mint(address(ceaInstance), 200e18);
        vm.deal(address(ceaInstance), 5 ether);

        // Record balances
        uint256 balance1Before = token1.balanceOf(address(ceaInstance));
        uint256 balance2Before = token2.balanceOf(address(ceaInstance));
        uint256 nativeBalanceBefore = address(ceaInstance).balance;

        // Execute migration
        executeMigration();

        // Verify all balances preserved
        assertEq(token1.balanceOf(address(ceaInstance)), balance1Before, "Token1 balance should be preserved");
        assertEq(token2.balanceOf(address(ceaInstance)), balance2Before, "Token2 balance should be preserved");
        assertEq(address(ceaInstance).balance, nativeBalanceBefore, "Native balance should be preserved");
    }

    // =========================================================================
    // Post-Migration Execution Tests
    // =========================================================================

    function test_PostMigration_Execute() public {
        // Execute migration
        executeMigration();

        // Execute a new transaction after migration
        bytes32 txID = generateTxID(100);
        bytes32 universalTxID = generateUniversalTxID(100);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({
            to: address(this),
            value: 0,
            data: abi.encodeWithSignature("dummyFunction()")
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify executed successfully
        assertTrue(ceaInstance.isExecuted(txID), "Post-migration execution should work");
    }

    function test_PostMigration_Multicall() public {
        // Execute migration
        executeMigration();

        // Execute a multicall after migration
        bytes32 txID = generateTxID(101);
        bytes32 universalTxID = generateUniversalTxID(101);

        Multicall[] memory calls = new Multicall[](3);
        calls[0] = Multicall({
            to: address(this),
            value: 0,
            data: abi.encodeWithSignature("dummyFunction()")
        });
        calls[1] = Multicall({
            to: address(this),
            value: 0,
            data: abi.encodeWithSignature("dummyFunction()")
        });
        calls[2] = Multicall({
            to: address(this),
            value: 0,
            data: abi.encodeWithSignature("dummyFunction()")
        });
        bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify executed successfully
        assertTrue(ceaInstance.isExecuted(txID), "Post-migration multicall should work");
    }

    // =========================================================================
    // Replay Protection Tests
    // =========================================================================

    function test_Migration_ReplayProtection() public {
        bytes32 txID = generateTxID(999);
        bytes32 universalTxID = generateUniversalTxID(999);
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        // Execute migration
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Attempt to replay same migration
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // Authorization Tests
    // =========================================================================

    function test_Migration_NotVault() public {
        bytes32 txID = generateTxID(999);
        bytes32 universalTxID = generateUniversalTxID(999);
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        address nonVault = makeAddr("nonVault");

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_Migration_WrongOriginCaller() public {
        bytes32 txID = generateTxID(999);
        bytes32 universalTxID = generateUniversalTxID(999);
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        address wrongUEA = makeAddr("wrongUEA");

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, wrongUEA, payload);
    }

    // =========================================================================
    // Multiple Migrations Tests
    // =========================================================================

    function test_MultipleMigrations_V1toV2toV3() public {
        // Migration 1: v1 → v2
        executeMigration();
        assertEq(
            CEAProxy(payable(address(ceaInstance))).getImplementation(),
            address(ceaV2Implementation),
            "Should be v2 after first migration"
        );

        // Deploy v3 and new migration contract
        CEA ceaV3Implementation = new CEA();
        CEAMigration migration2 = new CEAMigration(address(ceaV3Implementation));
        factory.setCEAMigrationContract(address(migration2));

        // Migration 2: v2 → v3
        bytes32 txID = generateTxID(1000);
        bytes32 universalTxID = generateUniversalTxID(1000);
        bytes memory payload = buildMigrationPayload(address(ceaInstance));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertEq(
            CEAProxy(payable(address(ceaInstance))).getImplementation(),
            address(ceaV3Implementation),
            "Should be v3 after second migration"
        );

        // Verify state still preserved
        assertEq(ceaInstance.UEA(), ueaOnPush, "UEA should still be preserved");
        assertEq(ceaInstance.VAULT(), vault, "VAULT should still be preserved");
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    function test_MigrationAfterManyExecutions() public {
        // Execute many transactions before migration
        for (uint256 i = 1; i <= 100; i++) {
            bytes32 txID = generateTxID(i);
            bytes32 universalTxID = generateUniversalTxID(i);

            Multicall[] memory calls = new Multicall[](1);
            calls[0] = Multicall({
                to: address(this),
                value: 0,
                data: abi.encodeWithSignature("dummyFunction()")
            });
            bytes memory payload = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));

            vm.prank(vault);
            ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
        }

        // Verify all executed
        for (uint256 i = 1; i <= 100; i++) {
            assertTrue(ceaInstance.isExecuted(generateTxID(i)), "Transaction should be executed");
        }

        // Execute migration
        executeMigration();

        // Verify all isExecuted entries preserved
        for (uint256 i = 1; i <= 100; i++) {
            assertTrue(ceaInstance.isExecuted(generateTxID(i)), "isExecuted should be preserved");
        }
    }

    function test_MigrationEmptyState() public {
        // Deploy fresh CEA with no prior executions
        address freshUEA = makeAddr("freshUEA");
        vm.prank(vault);
        address freshCEA = factory.deployCEA(freshUEA);

        CEA freshCEAInstance = CEA(payable(freshCEA));

        // Execute migration immediately
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildMigrationPayload(freshCEA);

        vm.prank(vault);
        freshCEAInstance.executeUniversalTx(txID, universalTxID, freshUEA, payload);

        // Verify migration successful
        assertEq(
            CEAProxy(payable(freshCEA)).getImplementation(),
            address(ceaV2Implementation),
            "Fresh CEA should be migrated"
        );
    }

    // =========================================================================
    // Dummy Function
    // =========================================================================

    function dummyFunction() external pure returns (bool) {
        return true;
    }
}
