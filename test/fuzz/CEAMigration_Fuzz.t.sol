// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import {CEA} from "../../src/cea/CEA.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {CEAMigration} from "../../src/cea/CEAMigration.sol";
import {ICEA} from "../../src/interfaces/ICEA.sol";
import {CEAErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract CEAMigration_FuzzTest is Test {
    bytes32 private constant CEA_LOGIC_SLOT =
        0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    CEA public ceaV1;
    CEA public ceaV2;
    CEAProxy public ceaProxyImpl;
    CEAFactory public factory;
    MockUniversalGateway public mockUniversalGateway;
    CEAMigration public migration;

    address public owner;
    address public vault;
    address public ueaOnPush;

    function setUp() public {
        owner = address(this);
        vault = makeAddr("vault");
        ueaOnPush = makeAddr("ueaOnPush");
        mockUniversalGateway = new MockUniversalGateway();

        ceaV1 = new CEA();
        ceaV2 = new CEA();
        ceaProxyImpl = new CEAProxy();

        CEAFactory factoryImpl = new CEAFactory();
        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            makeAddr("pauser"),
            vault,
            address(ceaProxyImpl),
            address(ceaV1),
            address(mockUniversalGateway)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));

        migration = new CEAMigration(address(ceaV2));
    }

    // =========================================================================
    // 11.1 Delegatecall Enforcement Properties
    // =========================================================================

    /// @dev Direct call to migrateCEA() from any address always reverts with Unauthorized.
    function testFuzz_migrateCEA_directCall_reverts(address caller) public {
        vm.assume(caller != address(0));

        vm.expectRevert(CommonErrors.Unauthorized.selector);
        vm.prank(caller);
        migration.migrateCEA();
    }

    // =========================================================================
    // 11.2 Migration Execution Properties
    // =========================================================================

    /// @dev After delegatecall to migrateCEA(), CEA_LOGIC_SLOT contains CEA_IMPLEMENTATION.
    function testFuzz_migrateCEA_viaDelegatecall_updatesSlot() public {
        // Deploy a CEA and set migration contract on factory
        vm.prank(vault);
        address ceaAddr = factory.deployCEA(ueaOnPush);

        factory.setCEAMigrationContract(address(migration));

        // Verify initial slot value (should be ceaV1)
        bytes32 slotBefore = vm.load(ceaAddr, CEA_LOGIC_SLOT);
        assertEq(address(uint160(uint256(slotBefore))), address(ceaV1));

        // Trigger migration via executeUniversalTx with MIGRATION_SELECTOR payload
        bytes memory payload = abi.encodePacked(
            bytes4(keccak256("UEA_MIGRATION"))
        );
        bytes32 txId = keccak256("migration_slot_test");

        vm.prank(vault);
        ICEA(ceaAddr).executeUniversalTx(
            txId, bytes32(0), ueaOnPush, address(0), payload
        );

        // Verify slot was updated to ceaV2
        bytes32 slotAfter = vm.load(ceaAddr, CEA_LOGIC_SLOT);
        assertEq(address(uint160(uint256(slotAfter))), address(ceaV2));
    }

    /// @dev Migration emits ImplementationUpdated with the correct new implementation address.
    function testFuzz_migrateCEA_emitsEvent() public {
        vm.prank(vault);
        address ceaAddr = factory.deployCEA(ueaOnPush);

        factory.setCEAMigrationContract(address(migration));

        bytes memory payload = abi.encodePacked(
            bytes4(keccak256("UEA_MIGRATION"))
        );
        bytes32 txId = keccak256("migration_event_test");

        vm.expectEmit(true, false, false, false);
        emit CEAMigration.ImplementationUpdated(address(ceaV2));

        vm.prank(vault);
        ICEA(ceaAddr).executeUniversalTx(
            txId, bytes32(0), ueaOnPush, address(0), payload
        );
    }

    // =========================================================================
    // 11.3 Constructor Validation Properties
    // =========================================================================

    /// @dev Constructor with address(0) reverts with CEAErrors.InvalidInput.
    function testFuzz_constructor_zeroImplementation_reverts() public {
        vm.expectRevert(CEAErrors.InvalidInput.selector);
        new CEAMigration(address(0));
    }

    /// @dev Constructor with an address that has no deployed code reverts with InvalidInput.
    function testFuzz_constructor_noCodeImplementation_reverts(address noCodeAddr) public {
        // Avoid precompiles and addresses that might have code
        vm.assume(noCodeAddr > address(0x10));
        vm.assume(noCodeAddr.code.length == 0);

        vm.expectRevert(CEAErrors.InvalidInput.selector);
        new CEAMigration(noCodeAddr);
    }
}
