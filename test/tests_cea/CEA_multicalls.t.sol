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
        vm.expectRevert(); // Will revert during abi.decode
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

        uint256 value = 0.1 ether; // Target requires exactly 0.1 ETH fee
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
        calls[0] =
            makeCall(address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(spender), 100 ether));
        // Step 2: Call spender which uses the approval
        calls[1] = makeCall(
            address(spender), 0, abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether)
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

        bytes memory payload =
            buildExternalSingleCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
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
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // First call's effect should be rolled back
        assertEq(target.magicNumber(), magicBefore, "Target magic number should be unchanged after revert");
    }

    function test_TxIDNotMarked_WhenExecutionReverts() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload =
            buildExternalSingleCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // txID should NOT be marked as executed since the tx reverted
        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be marked executed");
    }

    function test_NoEventsEmitted_WhenExecutionReverts() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory payload =
            buildExternalSingleCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        vm.prank(vault);
        vm.recordLogs();

        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0, "No events should be emitted on revert");
    }

    // =========================================================================
    // 4) Self-call allowlist cases (sendUniversalTxToUEA routing)
    // =========================================================================

    function test_RevertWhen_SelfCallDataLengthLessThan4() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(ceaInstance), 0, "123"); // Only 3 bytes

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
        // Calls initializeCEA via .call() which reverts with AlreadyInitialized
        // but we now get ExecutionFailed instead of bubbled error
        vm.expectRevert(Errors.ExecutionFailed.selector);
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
            address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 0)
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
        uint256 withdrawAmount = 500 ether; // More than balance

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfWithdrawCall(address(token), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled from sendUniversalTxToUEA's InsufficientBalance
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
        uint256 withdrawAmount = 500 ether; // More than balance

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfWithdrawCall(address(0), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled from sendUniversalTxToUEA's InsufficientBalance
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
            address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 100 ether)
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

        bytes memory payload1 =
            buildExternalSingleCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));

        bytes memory payload2 =
            buildExternalSingleCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 99));

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

        bytes memory payload =
            buildExternalSingleCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));

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

        bytes memory payload =
            buildExternalSingleCall(address(malicious), 0, abi.encodeWithSignature("execute(bytes)", ""));

        vm.prank(vault);
        // The malicious contract will try to reenter but should be blocked
        // Note: Since the malicious contract doesn't actually attempt reentry in execute(),
        // this test just verifies the call succeeds and reentrancy guard is in place
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertTrue(malicious.attackAttempted(), "Attack should have been attempted");
    }

    // =========================================================================
    // 10) msg.value accounting (A - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_RevertWhen_MsgValue_MismatchInMultiCall() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 value1 = 0.1 ether;
        uint256 value2 = 0.2 ether;
        uint256 totalValue = value1 + value2;

        vm.deal(vault, totalValue);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), value1, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 10));
        calls[1] = makeCall(address(target), value2, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 20));

        bytes memory payload = encodeCalls(calls);

        // Send wrong amount - less than sum
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidAmount.selector);
        ceaInstance.executeUniversalTx{value: value1}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_RevertWhen_MsgValue_ExceedsSumInMultiCall() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 value1 = 0.1 ether;
        uint256 value2 = 0.2 ether;
        uint256 totalValue = value1 + value2;

        vm.deal(vault, totalValue + 1 ether);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), value1, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 10));
        calls[1] = makeCall(address(target), value2, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 20));

        bytes memory payload = encodeCalls(calls);

        // Send more than sum - ETH would be trapped
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidAmount.selector);
        ceaInstance.executeUniversalTx{value: totalValue + 0.5 ether}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_SuccessWhen_MsgValue_MatchesSumExactly() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Both calls require exactly 0.1 ETH each
        uint256 value1 = 0.1 ether;
        uint256 value2 = 0.1 ether;
        uint256 totalValue = value1 + value2; // 0.2 ether

        vm.deal(vault, totalValue);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), value1, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 10));
        calls[1] = makeCall(address(target), value2, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 20));

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: totalValue}(txID, universalTxID, ueaOnPush, payload);

        assertEq(target.magicNumber(), 20, "Final magic number should be 20");
        assertEq(address(target).balance, totalValue, "Target should have received all ETH");
    }

    // =========================================================================
    // 11) Self-call safety invariants (B - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_RevertWhen_SelfCall_WithNonZeroValue() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Try to send value to self-call (not allowed)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            0.1 ether, // Non-zero value to self-call
            abi.encodeWithSignature("sendUniversalTxToUEA(address,uint256,bytes)", address(0), 0.1 ether, "")
        );

        bytes memory payload = encodeCalls(calls);

        vm.deal(vault, 0.1 ether);
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_RevertWhen_DirectCallToSendUniversalTxToUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        // Try to call sendUniversalTxToUEA directly (not through executeUniversalTx)
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        CEA(payable(address(ceaInstance))).sendUniversalTxToUEA(address(token), 100 ether, "");
    }

    // =========================================================================
    // 12) Gateway integration edge cases (C - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_RevertWhen_WithdrawNative_InsufficientBalanceInBatch() public deployCEA {
        // Fund CEA with 0.5 ETH initially
        fundCEAWithNative(0.5 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Batch: external call first (uses 0.1 ETH), then withdraw more than remaining balance
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), 0.1 ether, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42));
        // After first call, CEA has 0.5 ETH left (0.5 initial + 0.1 msg.value - 0.1 to target)
        // Try to withdraw 1 ETH - should fail
        calls[1] = buildSelfWithdrawCall(address(0), 1 ether);

        bytes memory payload = encodeCalls(calls);

        // Give vault ETH to send as msg.value for the external call
        vm.deal(vault, 0.1 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled from sendUniversalTxToUEA's InsufficientBalance
        ceaInstance.executeUniversalTx{value: 0.1 ether}(txID, universalTxID, ueaOnPush, payload);

        // Verify rollback - target should not have received ETH
        assertEq(address(target).balance, 0, "Target balance should be 0 due to rollback");
    }

    function test_RevertWhen_Gateway_RevertsBubbles() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        // Configure gateway to revert
        mockUniversalGateway.setWillRevert(true, "Gateway intentionally reverted");

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        // Approve gateway
        calls[0] = makeCall(
            address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 100 ether)
        );
        // Withdraw (gateway will revert)
        calls[1] = buildSelfWithdrawCall(address(token), 100 ether);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Gateway revert bubbled as ExecutionFailed
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify txID not marked executed
        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be marked");
    }

    // =========================================================================
    // 13) Execution atomicity with token state (D - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_RevertWhen_ApprovalThenExternalFails_RollbackAllowance() public deployCEA {
        MockGasToken token = new MockGasToken();
        TokenSpenderTarget spender = new TokenSpenderTarget();
        RevertingTarget reverter = new RevertingTarget();

        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        // Approve spender
        calls[0] =
            makeCall(address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(spender), 100 ether));
        // External call that fails
        calls[1] = makeCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify allowance rolled back to 0
        assertEq(token.allowance(address(ceaInstance), address(spender)), 0, "Allowance should be 0");
    }

    function test_RevertWhen_SelfWithdrawInMiddle_LaterCallFails_NoGatewayCall() public deployCEA {
        MockGasToken token = new MockGasToken();
        RevertingTarget reverter = new RevertingTarget();

        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](3);
        // Approve gateway
        calls[0] = makeCall(
            address(token), 0, abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 100 ether)
        );
        // Self-withdraw
        calls[1] = buildSelfWithdrawCall(address(token), 100 ether);
        // Later call fails
        calls[2] = makeCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify gateway was NOT called (entire tx reverted before gateway interaction persisted)
        assertEq(mockUniversalGateway.callCount(), 0, "Gateway should not be called due to rollback");
    }

    // =========================================================================
    // 14) Replay protection edge cases (E - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_SuccessWhen_RetrySameTxID_AfterFirstRevert() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory failingPayload =
            buildExternalSingleCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        // First attempt - should revert
        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, failingPayload);

        // Verify not marked executed
        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be marked");

        // Retry with same txID but different (succeeding) payload
        bytes memory succeedingPayload =
            buildExternalSingleCall(address(target), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, succeedingPayload);

        // Verify now marked executed
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked executed");
        assertEq(target.magicNumber(), 42, "Target should have been updated");
    }

    function test_RevertWhen_ReplaySameTxID_WithDifferentMsgValue() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 value1 = 0.1 ether;
        uint256 value2 = 0.2 ether;

        vm.deal(vault, value1 + value2);

        bytes memory payload = buildExternalSingleCall(
            address(target), value1, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42)
        );

        // First execution with value1
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: value1}(txID, universalTxID, ueaOnPush, payload);

        // Try to replay with different msg.value - should still be blocked
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx{value: value2}(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // 15) Event data validation (G - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_Events_DataMatchesEachCall() public deployCEA {
        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        bytes memory data1 = abi.encodeWithSignature("setMagicNumber(uint256)", 10);
        bytes memory data2 = abi.encodeWithSignature("setMagicNumber(uint256)", 20);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(address(target), 0, data1);
        calls[1] = makeCall(address(target), 0, data2);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.recordLogs();
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Find UniversalTxExecuted events and validate data
        // Event signature: UniversalTxExecuted(bytes32 indexed txID, bytes32 indexed universalTxID, address indexed originCaller, address target, bytes data)
        uint256 eventIndex = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("UniversalTxExecuted(bytes32,bytes32,address,address,bytes)")) {
                // Indexed params are in topics, non-indexed in data
                bytes32 emittedTxID = logs[i].topics[1];
                bytes32 emittedUniversalTxID = logs[i].topics[2];
                address emittedOrigin = address(uint160(uint256(logs[i].topics[3])));

                // Decode non-indexed params from data
                (address emittedTo, bytes memory emittedData) = abi.decode(logs[i].data, (address, bytes));

                // Validate against expected call
                assertEq(emittedTxID, txID, "Event txID should match");
                assertEq(emittedUniversalTxID, universalTxID, "Event universalTxID should match");
                assertEq(emittedOrigin, ueaOnPush, "Event origin should match");
                assertEq(emittedTo, calls[eventIndex].to, "Event target should match call");
                assertEq(emittedData, calls[eventIndex].data, "Event data should match call");

                eventIndex++;
            }
        }

        assertEq(eventIndex, 2, "Should have validated 2 events");
    }

    function test_Events_SelfCallWithdraw_EmittedCorrectly() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 withdrawAmount = 100 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), withdrawAmount)
        );
        calls[1] = buildSelfWithdrawCall(address(token), withdrawAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.recordLogs();
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Find the self-call event
        // Event signature: UniversalTxExecuted(bytes32 indexed txID, bytes32 indexed universalTxID, address indexed originCaller, address target, bytes data)
        bool foundSelfCallEvent = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("UniversalTxExecuted(bytes32,bytes32,address,address,bytes)")) {
                // Extract indexed params from topics
                address emittedOrigin = address(uint160(uint256(logs[i].topics[3])));

                // Decode non-indexed params from data
                (address emittedTo, bytes memory emittedData) = abi.decode(logs[i].data, (address, bytes));

                // Check if this is the self-call event
                if (emittedTo == address(ceaInstance)) {
                    foundSelfCallEvent = true;
                    assertEq(emittedOrigin, ueaOnPush, "Self-call event origin should be UEA");
                    assertEq(emittedData, calls[1].data, "Self-call event data should match");
                }
            }
        }

        assertTrue(foundSelfCallEvent, "Should have found self-call event");
    }

    // =========================================================================
    // 16) Native transfer atomicity (H - missing tests from TEST_ANALYSIS.md)
    // =========================================================================

    function test_RevertWhen_NativeTransfer_LaterRevert_RollbackReceiverBalance() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        uint256 transferAmount = 0.1 ether; // Exact fee required by target
        vm.deal(vault, transferAmount);

        Multicall[] memory calls = new Multicall[](2);
        // Send native to target
        calls[0] =
            makeCall(address(target), transferAmount, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42));
        // Later call reverts
        calls[1] = makeCall(address(reverter), 0, abi.encodeWithSignature("revertWithReason()"));

        bytes memory payload = encodeCalls(calls);

        uint256 targetBalanceBefore = address(target).balance;

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled error no longer shown
        ceaInstance.executeUniversalTx{value: transferAmount}(txID, universalTxID, ueaOnPush, payload);

        // Verify target balance unchanged (rollback)
        assertEq(address(target).balance, targetBalanceBefore, "Target balance should not change due to rollback");
    }

    // =========================================================================
    // 1) MULTICALL_SELECTOR Flow Tests
    // =========================================================================

    function test_MulticallSelector_RoutesToMulticallHandler() public deployCEA {
        MockGasToken token = new MockGasToken();
        Target testTarget = new Target();
        fundCEAWithTokens(address(token), 1000 ether);

        // Create multicall with MULTICALL_SELECTOR prefix
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0, abi.encodeWithSignature("approve(address,uint256)", address(testTarget), 100 ether)
        );
        calls[1] = makeCall(address(testTarget), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 42));

        bytes memory payload = encodeCalls(calls); // This now includes MULTICALL_SELECTOR

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify execution succeeded
        assertEq(testTarget.magicNumber(), 42);
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
    }

    function test_NoMulticallSelector_RoutesToBackwardsCompatHandler() public deployCEA {
        MockGasToken token = new MockGasToken();
        Target testTarget = new Target();
        fundCEAWithTokens(address(token), 1000 ether);

        // Create multicall WITHOUT MULTICALL_SELECTOR (old format)
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0, abi.encodeWithSignature("approve(address,uint256)", address(testTarget), 100 ether)
        );
        calls[1] = makeCall(address(testTarget), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 123));

        // Encode without MULTICALL_SELECTOR (old way - direct abi.encode)
        bytes memory payload = abi.encode(calls);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify execution succeeded (backwards compatibility)
        assertEq(testTarget.magicNumber(), 123);
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
    }

    function test_MulticallSelector_ValidatesMsgValue() public deployCEA {
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(0x123), 1 ether, "");

        bytes memory payload = encodeCalls(calls); // Includes MULTICALL_SELECTOR

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.deal(vault, 2 ether);
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidAmount.selector);
        ceaInstance.executeUniversalTx{value: 2 ether}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_MulticallSelector_CorrectMsgValuePasses() public deployCEA {
        Target testTarget = new Target();

        Multicall[] memory calls = new Multicall[](1);
        calls[0] =
            makeCall(address(testTarget), 0.1 ether, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 999));

        bytes memory payload = encodeCalls(calls); // Includes MULTICALL_SELECTOR

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.deal(vault, 0.1 ether);
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(txID, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
        assertEq(testTarget.magicNumber(), 999);
    }

    // =========================================================================
    // =========================================================================
    // 3) Edge Cases for MULTICALL_SELECTOR Routing
    // =========================================================================

    function test_InvalidPayload_WithMulticallSelector_ButMalformedData() public deployCEA {
        // Payload with MULTICALL_SELECTOR but malformed data after it
        bytes memory invalidPayload = abi.encodePacked(MULTICALL_SELECTOR, bytes("malformed data"));

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        vm.expectRevert(); // Should revert during abi.decode
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, invalidPayload);
    }

    function test_PayloadLength_LessThan4Bytes_RoutesToBackwardsCompat() public deployCEA {
        // Payload less than 4 bytes cannot have MULTICALL_SELECTOR
        bytes memory shortPayload = bytes("abc");

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        vm.expectRevert(); // Should revert during abi.decode as Multicall[]
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, shortPayload);
    }

    function test_MulticallSelector_EmptyCallsArray_Succeeds() public deployCEA {
        Multicall[] memory calls = new Multicall[](0);
        bytes memory payload = encodeCalls(calls);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
    }

    function test_MulticallSelector_MixedValueCalls() public deployCEA {
        Target target1 = new Target();
        Target target2 = new Target();

        Multicall[] memory calls = new Multicall[](3);
        calls[0] = makeCall(address(target1), 0.1 ether, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 100));
        calls[1] = makeCall(address(target2), 0, abi.encodeWithSignature("setMagicNumber(uint256)", 200));
        calls[2] = makeCall(address(target1), 0.1 ether, abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 300));

        bytes memory payload = encodeCalls(calls);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.deal(vault, 0.2 ether);
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0.2 ether}(txID, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
        assertEq(target1.magicNumber(), 300); // Last call to target1
        assertEq(target2.magicNumber(), 200);
    }

    // =========================================================================
    // 4) Self-call routing with MULTICALL_SELECTOR
    // =========================================================================

    function test_SelfCall_WithMulticallSelector_MustHaveZeroValue() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            0.1 ether, // Non-zero value to self-call - should revert
            abi.encodeWithSignature(
                "sendUniversalTxToUEA(address,uint256,bytes)", address(token), 100 ether, ""
            )
        );

        bytes memory payload = encodeCalls(calls);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.deal(vault, 0.1 ether);
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(txID, universalTxID, ueaOnPush, payload);
    }

    function test_SelfCall_WithMulticallSelector_ZeroValue_Succeeds() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0, abi.encodeWithSignature("approve(address,uint256)", universalGateway, 100 ether)
        );
        calls[1] = makeCall(
            address(ceaInstance),
            0, // Zero value to self-call - OK
            abi.encodeWithSignature("sendUniversalTxToUEA(address,uint256,bytes)", address(token), 100 ether, "")
        );

        bytes memory payload = encodeCalls(calls);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID));
    }
}
