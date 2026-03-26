// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";

import "../../src/libraries/Types.sol";
import {UEAErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {UEA_EVM} from "../../src/uea/UEA_EVM.sol";
import {UEA_SVM} from "../../src/uea/UEA_SVM.sol";
import {UEAProxy} from "../../src/uea/UEAProxy.sol";
import {UEAMigration} from "../../src/uea/UEAMigration.sol";
import {UEAFactory} from "../../src/uea/UEAFactory.sol";
import {IUEA} from "../../src/interfaces/IUEA.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Helper that performs delegatecall to a migration contract.
///      Used to test migration execution in a proxy-like context.
contract DelegatecallProxy {
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    function delegateToMigrateEVM(address migration) external returns (bool success) {
        bytes memory callData = abi.encodeWithSignature("migrateUEAEVM()");
        (success,) = migration.delegatecall(callData);
    }

    function delegateToMigrateSVM(address migration) external returns (bool success) {
        bytes memory callData = abi.encodeWithSignature("migrateUEASVM()");
        (success,) = migration.delegatecall(callData);
    }

    function getSlotValue() external view returns (address impl) {
        bytes32 slot = UEA_LOGIC_SLOT;
        assembly {
            impl := sload(slot)
        }
    }
}

contract UEAMigration_FuzzTest is Test {
    UEA_EVM ueaEVMImpl;
    UEA_SVM ueaSVMImpl;
    UEAMigration migration;

    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    function setUp() public {
        ueaEVMImpl = new UEA_EVM();
        ueaSVMImpl = new UEA_SVM();
        migration = new UEAMigration(address(ueaEVMImpl), address(ueaSVMImpl));
    }

    // =========================================================================
    // 7.1 Direct call always reverts (onlyDelegateCall enforcement)
    // =========================================================================

    function testFuzz_migrateUEAEVM_directCall_reverts(address caller) public {
        vm.prank(caller);
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEAEVM();
    }

    function testFuzz_migrateUEASVM_directCall_reverts(address caller) public {
        vm.prank(caller);
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        migration.migrateUEASVM();
    }

    // =========================================================================
    // 7.2 Delegatecall updates UEA_LOGIC_SLOT
    // =========================================================================

    function testFuzz_migrateUEAEVM_updatesSlot() public {
        DelegatecallProxy dcProxy = new DelegatecallProxy();

        // Before migration: slot is zero
        assertEq(dcProxy.getSlotValue(), address(0));

        bool success = dcProxy.delegateToMigrateEVM(address(migration));
        assertTrue(success, "delegatecall to migrateUEAEVM should succeed");

        // After migration: slot contains EVM implementation address
        assertEq(dcProxy.getSlotValue(), migration.UEA_EVM_IMPLEMENTATION());
    }

    function testFuzz_migrateUEASVM_updatesSlot() public {
        DelegatecallProxy dcProxy = new DelegatecallProxy();

        // Before migration: slot is zero
        assertEq(dcProxy.getSlotValue(), address(0));

        bool success = dcProxy.delegateToMigrateSVM(address(migration));
        assertTrue(success, "delegatecall to migrateUEASVM should succeed");

        // After migration: slot contains SVM implementation address
        assertEq(dcProxy.getSlotValue(), migration.UEA_SVM_IMPLEMENTATION());
    }

    // =========================================================================
    // 7.3 Constructor validation
    // =========================================================================

    function testFuzz_constructor_zeroEVM_reverts(
        address /* svmImpl */
    )
        public
    {
        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        new UEAMigration(address(0), address(ueaSVMImpl));
    }

    function testFuzz_constructor_zeroSVM_reverts(
        address /* evmImpl */
    )
        public
    {
        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        new UEAMigration(address(ueaEVMImpl), address(0));
    }

    function testFuzz_constructor_sameImplementations_reverts(uint256 seed) public {
        // Deploy a fresh contract with code so both hasCode checks pass,
        // then the same-address check should fire.
        // We deploy either ueaEVMImpl or ueaSVMImpl depending on seed parity.
        address impl = (seed % 2 == 0) ? address(ueaEVMImpl) : address(ueaSVMImpl);

        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        new UEAMigration(impl, impl);
    }

    // Additional: no-code address for EVM reverts with InvalidInputArgs
    function testFuzz_constructor_noCodeEVM_reverts(address noCodeAddr) public {
        vm.assume(noCodeAddr != address(0));
        uint256 size;
        assembly {
            size := extcodesize(noCodeAddr)
        }
        vm.assume(size == 0);

        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        new UEAMigration(noCodeAddr, address(ueaSVMImpl));
    }

    // Additional: no-code address for SVM reverts with InvalidInputArgs
    function testFuzz_constructor_noCodeSVM_reverts(address noCodeAddr) public {
        vm.assume(noCodeAddr != address(0));
        uint256 size;
        assembly {
            size := extcodesize(noCodeAddr)
        }
        vm.assume(size == 0);

        vm.expectRevert(UEAErrors.InvalidInputArgs.selector);
        new UEAMigration(address(ueaEVMImpl), noCodeAddr);
    }
}
