// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./CEA.t.sol";
import "../../src/cea/CEAMigration.sol";
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import {MIGRATION_SELECTOR} from "../../src/libraries/Types.sol";

/// @title CEA_SingleCallTests
/// @notice Tests for CEA single-call execution path (park funds + single external call)
contract CEA_SingleCallTests is CEATest {
    // =========================================================================
    // Park Funds (empty payload)
    // =========================================================================

    function test_ParkFunds_EmptyPayload_NativeViaValue() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 amount = 1 ether;
        vm.deal(vault, amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, address(0), "");

        assertEq(address(ceaInstance).balance, amount, "CEA should hold parked native funds");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_ParkFunds_EmptyPayload_ERC20PreFunded() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 amount = 500 ether;
        fundCEAWithTokens(address(token), amount);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), "");

        assertEq(token.balanceOf(address(ceaInstance)), amount, "CEA should hold ERC20 tokens");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_ParkFunds_EmptyPayload_ZeroValue() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), "");

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_EmptyPayload_NonZeroRecipient_ForwardsNative() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 amount = 1 ether;
        vm.deal(vault, amount);

        address someRecipient = makeAddr("someRecipient");

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, someRecipient, "");

        // Empty payload + non-zero recipient is a plain native send to recipient, not fund-parking.
        // Fund-parking requires BOTH empty payload AND address(0) recipient.
        assertEq(address(someRecipient).balance, amount, "Recipient should receive the native funds");
        assertEq(address(ceaInstance).balance, 0, "CEA should not hold funds when recipient is non-zero");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_ParkFunds_EmitsEvent_TargetIsSelf() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);

        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(ceaInstance), "");

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), "");
    }

    // =========================================================================
    // Single Call Execution (non-empty payload)
    // =========================================================================

    function test_SingleCall_ExecuteTargetFunction() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);

        assertEq(target.getMagicNumber(), 42, "Target should have magic number set");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_SingleCall_ForwardsMsgValueToRecipient() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 amount = 0.1 ether;
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.deal(vault, amount);
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, address(target), payload);

        assertEq(target.getMagicNumber(), 42, "Target should have magic number set");
        assertEq(address(target).balance, amount, "Target should receive native value");
    }

    function test_SingleCall_ZeroValue_ValidRecipient() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 99);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);

        assertEq(target.getMagicNumber(), 99, "Target should have magic number set");
    }

    function test_SingleCall_EmitsEvent_CorrectTargetAndPayload() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 77);

        vm.prank(vault);

        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(target), payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);
    }

    // =========================================================================
    // Revert Cases
    // =========================================================================

    function test_SingleCall_RevertWhen_RecipientIsZero() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidRecipient.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), payload);
    }

    function test_SingleCall_RevertWhen_RecipientIsSelf() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidRecipient.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(ceaInstance), payload);
    }

    function test_SingleCall_RevertWhen_TargetReverts() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        vm.prank(vault);
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(reverter), payload);

        assertFalse(
            CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should not be marked executed on failure"
        );
    }

    function test_SingleCall_RevertWhen_NotVault() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);
    }

    function test_SingleCall_RevertWhen_WrongOriginCaller() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, makeAddr("wrongUEA"), address(target), payload);
    }

    function test_SingleCall_RevertWhen_DuplicateTxId() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);

        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(target), payload);
    }

    // =========================================================================
    // Path Isolation
    // =========================================================================

    function test_MulticallPayload_IgnoresRecipient() public deployCEA {
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 55));
        bytes memory payload = encodeCalls(calls);

        address randomRecipient = makeAddr("randomRecipient");

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, randomRecipient, payload);

        assertEq(target.getMagicNumber(), 55, "Multicall should execute normally regardless of recipient");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked executed");
    }

    function test_MigrationPayload_RevertsWhenRecipientNotSelf() public deployCEA {
        // Set up migration contract
        CEA ceaV2 = new CEA();
        CEAMigration migration = new CEAMigration(address(ceaV2));
        factory.setCEAMigrationContract(address(migration));

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodePacked(MIGRATION_SELECTOR);
        address randomRecipient = makeAddr("randomRecipient");

        // Migration with non-self recipient should revert
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidRecipient.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, randomRecipient, payload);
    }

    function test_MigrationPayload_SucceedsWhenRecipientIsSelf() public deployCEA {
        // Set up migration contract
        CEA ceaV2 = new CEA();
        CEAMigration migration = new CEAMigration(address(ceaV2));
        factory.setCEAMigrationContract(address(migration));

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = abi.encodePacked(MIGRATION_SELECTOR);

        // Migration with self recipient should succeed
        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(ceaInstance), payload);

        assertEq(
            CEAProxy(payable(address(ceaInstance))).getImplementation(),
            address(ceaV2),
            "Migration should succeed with self recipient"
        );
    }
}
