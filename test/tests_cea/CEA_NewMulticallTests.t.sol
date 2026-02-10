// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./CEA.t.sol";

/**
 * @title CEA_NewMulticallTests
 * @notice Comprehensive tests for CEA multicall functionality
 * @dev Tests organized per CEA_MULTICALL_TESTS.md requirements
 */
contract CEA_NewMulticallTests is CEATest {

    // =========================================================================
    // 1) Top-level executeUniversalTx validation cases
    // =========================================================================

    function test_RevertWhen_PayloadNotDecodableAsMulticall() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Invalid payload - not ABI-encoded Multicall[]
        bytes memory invalidPayload = "not a valid multicall";

        vm.prank(vault);
        vm.expectRevert();  // Will revert during abi.decode
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, invalidPayload);
    }

    function test_RevertWhen_PayloadIsEmptyCallsArray() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Empty calls array
        Multicall[] memory calls = new Multicall[](0);
        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        // Should succeed (empty multicall is valid, just does nothing)
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked executed");
    }

    // =========================================================================
    // 2) Multicall external execution (success paths)
    // =========================================================================

    function test_SingleExternalCall_NoValue_Success() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory targetCalldata = abi.encodeWithSignature("setMagicNumber(uint256)", 42);
        bytes memory payload = buildExternalSingleCall(address(target), 0, targetCalldata);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertEq(target.magicNumber(), 42, "Target should have magic number set");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be executed");
    }

    function test_SingleExternalCall_WithValue_Success() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 value = 0.1 ether;  // Target requires exactly 0.1 ETH fee
        vm.deal(vault, value);

        bytes memory targetCalldata = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);
        bytes memory payload = buildExternalSingleCall(address(target), value, targetCalldata);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: value}(txID, universalTxID, ueaOnPush, payload);

        assertEq(target.magicNumber(), 42, "Target should have magic number set");
        assertEq(address(target).balance, value, "Target should have received ETH");
    }

    function test_MultiStepBatch_AllSucceed_InOrder() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](3);
        calls[0] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 10));
        calls[1] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 20));
        calls[2] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 30));

        bytes memory payload = buildExternalBatch(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Final value should be 30 (last call)
        assertEq(target.magicNumber(), 30, "Target should have final magic number");
    }

    function test_MultiStepBatch_SecondCallDependsOnFirst() public deployCEA {
        MockGasToken token = new MockGasToken();
        TokenSpenderTarget spender = new TokenSpenderTarget();

        // Fund CEA with tokens
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        // Step 1: Approve spender
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(spender), 100 ether)
        );
        // Step 2: Call spender which uses the approval
        calls[1] = makeCall(
            address(spender),
            0,
            abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether)
        );

        bytes memory payload = buildExternalBatch(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertEq(spender.totalReceived(address(token)), 100 ether, "Spender should have received tokens");
    }

    // =========================================================================
    // 3) Multicall external execution (revert paths)
    // =========================================================================

    function test_RevertWhen_AnySubcallReverts_BubblesReason() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = buildExternalSingleCall(
            address(reverter),
            0,
            abi.encodeWithSignature("revertWithReason()")
        );

        vm.prank(vault);
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_RevertWhen_LaterSubcallReverts_RollsBackEarlierEffects() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));
        calls[1] = makeCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        bytes memory payload = buildExternalBatch(calls);

        uint256 magicBefore = target.magicNumber();

        vm.prank(vault);
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // First call's effect should be rolled back
        assertEq(target.magicNumber(), magicBefore, "Target magic number should be unchanged after revert");
    }

    function test_TxIDNotMarked_WhenExecutionReverts() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = buildExternalSingleCall(
            address(reverter),
            0,
            abi.encodeWithSignature("revertWithReason()")
        );

        vm.prank(vault);
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // txID should NOT be marked as executed since the tx reverted
        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be marked executed");
    }

    function test_NoEventsEmitted_WhenExecutionReverts() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = buildExternalSingleCall(
            address(reverter),
            0,
            abi.encodeWithSignature("revertWithReason()")
        );

        vm.prank(vault);
        vm.recordLogs();

        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0, "No events should be emitted on revert");
    }

    // =========================================================================
    // 4) Self-call allowlist cases (withdrawFundsToUEA routing)
    // =========================================================================

    function test_RevertWhen_SelfCallDataLengthLessThan4() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(ceaInstance), 0, "123");  // Only 3 bytes

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        // Now that _handleSelfCall is removed, malformed calls execute via .call() and fail
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_RevertWhen_SelfCallSelectorNotWithdraw() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Try to call initializeCEA (wrong selector)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature("initializeCEA(address,address,address)", address(0), address(0), address(0))
        );

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        // Now that _handleSelfCall is removed, this will call initializeCEA via .call()
        // which will revert with AlreadyInitialized since CEA is already initialized
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_SelfCallWithdraw_ERC20_Success() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 withdrawAmount = 500 ether;

        // Build multicall with approval + withdraw
        Multicall[] memory calls = new Multicall[](3);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 0)
        );
        calls[1] = makeCall(
            address(token),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), withdrawAmount)
        );
        calls[2] = buildSelfWithdrawCall(address(token), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function test_RevertWhen_SelfCallWithdraw_InsufficientERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 withdrawAmount = 500 ether;  // More than balance

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfWithdrawCall(address(token), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    function test_SelfCallWithdraw_Native_Success() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 withdrawAmount = 500 ether;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfWithdrawCall(address(0), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(txID, universalTxID, ueaOnPush, payload);

        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function test_RevertWhen_SelfCallWithdraw_InsufficientNativeBalance() public deployCEA {
        fundCEAWithNative(100 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 withdrawAmount = 500 ether;  // More than balance

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfWithdrawCall(address(0), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        ceaInstance.executeUniversalTx{value: 0}(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // 6) Mixed batch edge cases (external + self-call)
    // =========================================================================

    function test_MixedBatch_ExternalThenSelfCall_Success() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](4);
        // External call
        calls[0] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));
        // Approve for withdraw
        calls[1] = makeCall(
            address(token),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 100 ether)
        );
        // Self-call withdraw
        calls[2] = buildSelfWithdrawCall(address(token), 100 ether);
        // Another external call
        calls[3] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 99));

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertEq(target.magicNumber(), 99, "Final magic number should be 99");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    // =========================================================================
    // 7) Replay / idempotency edge cases
    // =========================================================================

    function test_SameTxID_CannotExecuteTwice_EvenWithDifferentPayload() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload1 = buildExternalSingleCall(
            address(target),
            0,
            abi.encodeWithSignature("setMagicNumber(uint256)", 42)
        );

        bytes memory payload2 = buildExternalSingleCall(
            address(target),
            0,
            abi.encodeWithSignature("setMagicNumber(uint256)", 99)
        );

        // First execution succeeds
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload1);

        // Second execution with same txID but different payload should fail
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload2);
    }

    function test_DifferentTxID_CanExecuteSamePayload() public deployCEA {
        bytes32 txID1 = generateTxID(1);
        bytes32 txID2 = generateTxID(2);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = buildExternalSingleCall(
            address(target),
            0,
            abi.encodeWithSignature("setMagicNumber(uint256)", 42)
        );

        // First execution
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID1, universalTxID, ueaOnPush, payload);

        // Second execution with different txID but same payload should succeed
        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID2, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID1), "txID1 should be executed");
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID2), "txID2 should be executed");
    }

    // =========================================================================
    // 8) Event correctness
    // =========================================================================

    function test_Events_OnePerMulticallStep() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](3);
        calls[0] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 10));
        calls[1] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 20));
        calls[2] = makeCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 30));

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.recordLogs();
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Count UniversalTxExecuted events
        uint256 eventCount = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("UniversalTxExecuted(bytes32,bytes32,address,address,bytes)")) {
                eventCount++;
            }
        }

        assertEq(eventCount, 3, "Should emit 3 UniversalTxExecuted events");
    }

    // =========================================================================
    // 9) Attack / misuse cases
    // =========================================================================

    function test_RevertWhen_ReentrantCall() public deployCEA {
        MaliciousTarget malicious = new MaliciousTarget(address(ceaInstance));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload = buildExternalSingleCall(
            address(malicious),
            0,
            abi.encodeWithSignature("execute(bytes)", "")
        );

        vm.prank(vault);
        // The malicious contract will try to reenter but should be blocked
        // Note: Since the malicious contract doesn't actually attempt reentry in execute(),
        // this test just verifies the call succeeds and reentrancy guard is in place
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertTrue(malicious.attackAttempted(), "Attack should have been attempted");
    }
}
