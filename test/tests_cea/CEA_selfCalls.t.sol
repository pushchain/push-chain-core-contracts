// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./CEA.t.sol";
import {Target} from "../../src/mocks/Target.sol";

/**
 * @title CEA_ComprehensiveTests
 * @notice Comprehensive edge case tests for sendUniversalTxToUEA function
 * @dev Tests missing critical edge cases identified in Final_TESTS.sol
 */
contract CEA_ComprehensiveTests is CEATest {

    // Event declaration (from ICEA interface)
    event UniversalTxToUEA(address indexed _cea, address indexed _uea, address indexed token, uint256 amount);

    // =========================================================================
    // 1) UniversalTxRequest Field Verification Tests
    // =========================================================================

    function test_UniversalTxRequest_RecipientIsUEA_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), amount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify UniversalTxRequest.recipient == UEA
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.recipient, ueaOnPush, "Recipient should be UEA");
    }

    function test_UniversalTxRequest_RecipientIsUEA_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), amount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(txID, universalTxID, ueaOnPush, payload);

        // Verify UniversalTxRequest.recipient == UEA
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.recipient, ueaOnPush, "Recipient should be UEA");
    }

    function test_UniversalTxRequest_RevertInstructionFundRecipientIsUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), amount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify revertInstruction.fundRecipient == UEA
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.revertInstruction.fundRecipient, ueaOnPush, "RevertInstruction fundRecipient should be UEA");
    }

    function test_UniversalTxRequest_RevertInstructionRevertMsgIsEmpty() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), amount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify revertInstruction.revertMsg == ""
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.revertInstruction.revertMsg, "", "RevertInstruction revertMsg should be empty");
    }

    // =========================================================================
    // =========================================================================
    // 3) Maximum Value Transfer Tests
    // =========================================================================

    function test_SendUniversalTxToUEA_Send100PercentOfBalance_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 totalBalance = 1000 ether;
        fundCEAWithTokens(address(token), totalBalance);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, totalBalance)
        );
        calls[1] = buildSelfSendToUEACall(address(token), totalBalance);

        bytes memory payload = encodeCalls(calls);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));
        assertEq(balanceBefore, totalBalance, "CEA should have full balance before");

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify CEA balance is exactly 0 after sending 100%
        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, totalBalance, "CEA balance (mock doesn't transfer, so unchanged)");

        // Verify gateway was called with full amount
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.amount, totalBalance, "Should send 100% of balance");
    }

    function test_SendUniversalTxToUEA_Send100PercentOfBalance_Native() public deployCEA {
        uint256 totalBalance = 10 ether;
        fundCEAWithNative(totalBalance);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), totalBalance);

        bytes memory payload = encodeCalls(calls);

        uint256 balanceBefore = address(ceaInstance).balance;
        assertEq(balanceBefore, totalBalance, "CEA should have full balance before");

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(txID, universalTxID, ueaOnPush, payload);

        // Verify CEA balance is exactly 0 after sending 100%
        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, 0, "CEA balance should be exactly 0 after sending 100%");

        // Verify gateway was called with full amount
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.amount, totalBalance, "Should send 100% of balance");
    }

    // =========================================================================
    // 4) Minimum Value Transfer Tests
    // =========================================================================

    function test_SendUniversalTxToUEA_MinimumAmount_1Wei_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 minAmount = 1 wei;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, minAmount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), minAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.amount, minAmount, "Should handle 1 wei minimum amount");
    }

    function test_SendUniversalTxToUEA_MinimumAmount_1Wei_Native() public deployCEA {
        fundCEAWithNative(10 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 minAmount = 1 wei;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), minAmount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(txID, universalTxID, ueaOnPush, payload);

        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.amount, minAmount, "Should handle 1 wei minimum amount");
    }

    // =========================================================================
    // 5) Multiple sendUniversalTxToUEA Calls in Same Multicall
    // =========================================================================

    function test_MultipleSendUniversalTxToUEA_InSameMulticall() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 2000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](4);
        // First send
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, 500 ether)
        );
        calls[1] = buildSelfSendToUEACall(address(token), 500 ether);

        // Second send
        calls[2] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, 300 ether)
        );
        calls[3] = buildSelfSendToUEACall(address(token), 300 ether);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify both calls went through
        assertEq(mockUniversalGateway.callCount(), 2, "Gateway should be called twice");
    }

    // =========================================================================
    // 7) Native Token Balance Changes During Execution
    // =========================================================================

    function test_SendUniversalTxToUEA_Native_BalanceChangeDuringMulticall() public deployCEA {
        // Start with 0.4 ETH in CEA
        fundCEAWithNative(0.4 ether);

        Target payableTarget = new Target();

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](2);
        // First call: Send 0.1 ETH to target (via msg.value from multicall)
        calls[0] = makeCall(
            address(payableTarget),
            0.1 ether,
            abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42)
        );
        // Second call: Send 0.4 ETH to UEA (0.4 initial balance remains after first call)
        calls[1] = buildSelfSendToUEACall(address(0), 0.4 ether);

        bytes memory payload = encodeCalls(calls);

        // CEA starts with 0.4 ETH
        // Multicall adds 0.1 ETH via msg.value → CEA has 0.5 ETH total
        // After first call (send 0.1 to target) → CEA has 0.4 ETH
        // After second call (send 0.4 to UEA) → CEA has 0 ETH
        vm.deal(vault, 0.1 ether);
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(txID, universalTxID, ueaOnPush, payload);

        // Verify gateway was called with 0.4 ETH
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.amount, 0.4 ether, "Should send 0.4 ETH");
    }

    // =========================================================================
    // 8) Edge Case: Amount == type(uint256).max (Overflow Protection)
    // =========================================================================

    function test_SendUniversalTxToUEA_MaxUint256Amount_RevertsInsufficientBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(token), type(uint256).max);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled InsufficientBalance
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // =========================================================================
    //       SelfCalls: FUNDS_AND_PAYLOAD
    // =========================================================================
    // =========================================================================

    // =========================================================================
    // 1) Access Control & Call-Path Integrity (Self-call Only via CEA)
    // =========================================================================

    function test_FundsAndPayload_RevertWhen_DirectCall_NotSelfCall() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        vm.expectRevert(CommonErrors.Unauthorized.selector);
        CEA(payable(address(ceaInstance))).sendUniversalTxToUEA(
            address(token), 500 ether, ueaPayload
        );
    }

    function test_FundsAndPayload_RevertWhen_CalledByVaultDirectly() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        vm.prank(vault);
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        CEA(payable(address(ceaInstance))).sendUniversalTxToUEA(
            address(token), 500 ether, ueaPayload
        );
    }

    function test_FundsAndPayload_RevertWhen_CalledByEOA() public deployCEA {
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        vm.prank(makeAddr("randomEOA"));
        vm.expectRevert(CommonErrors.Unauthorized.selector);
        CEA(payable(address(ceaInstance))).sendUniversalTxToUEA(
            address(0), 1 ether, ueaPayload
        );
    }

    // =========================================================================
    // 2) Input Validation (Amount / Token / Payload)
    // =========================================================================

    function test_FundsAndPayload_RevertWhen_ZeroAmount_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), 0, ueaPayload)
        );

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    function test_FundsAndPayload_RevertWhen_ZeroAmount_Native() public deployCEA {
        fundCEAWithNative(1 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), 0, ueaPayload)
        );

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    function test_FundsAndPayload_RevertWhen_InsufficientNativeBalance() public deployCEA {
        fundCEAWithNative(0.1 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), 1 ether, ueaPayload)
        );

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    function test_FundsAndPayload_RevertWhen_InsufficientERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);

        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), 500 ether)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), 500 ether, ueaPayload)
        );

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    // =========================================================================
    // 3) Correct Gateway Function Selection (Core Behavior)
    // =========================================================================

    function test_FundsAndPayload_Native_CallsSendUniversalTxViaCEA() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "Should call sendUniversalTxViaCEA for non-empty payload");
        assertEq(mockUniversalGateway.viaCEACallCount(), 1, "viaCEA call count should be 1");
    }

    function test_FundsAndPayload_ERC20_CallsSendUniversalTxViaCEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "Should call sendUniversalTxViaCEA for non-empty payload");
    }

    function test_FundsOnly_Native_CallsSendUniversalTxViaCEA() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "Should call sendUniversalTxViaCEA for all tx types");
        assertEq(mockUniversalGateway.viaCEACallCount(), 1, "viaCEA call count should be 1");
    }

    function test_FundsOnly_ERC20_CallsSendUniversalTxViaCEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "Should call sendUniversalTxViaCEA for all tx types");
    }

    // =========================================================================
    // 4) Correct Request Construction (Req Field-Level Assertions)
    // =========================================================================

    function test_FundsAndPayload_ReqFieldsCorrect_Native() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "req.recipient should be UEA");
        assertEq(req.token, address(0), "req.token should be address(0) for native");
        assertEq(req.amount, amount, "req.amount should match");
        assertEq(req.payload, ueaPayload, "req.payload should match the passed-in payload");
        assertEq(req.signatureData.length, 0, "req.signatureData should be empty");
        assertEq(req.revertInstruction.fundRecipient, ueaOnPush, "fundRecipient should be UEA");
        assertEq(req.revertInstruction.revertMsg, "", "revertMsg should be empty");
    }

    function test_FundsAndPayload_ReqFieldsCorrect_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = hex"deadbeef";

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "req.recipient should be UEA");
        assertEq(req.token, address(token), "req.token should match token");
        assertEq(req.amount, amount, "req.amount should match");
        assertEq(req.payload, ueaPayload, "req.payload should match exact bytes");
        assertEq(req.signatureData.length, 0, "req.signatureData should be empty");
        assertEq(req.revertInstruction.fundRecipient, ueaOnPush, "fundRecipient should be UEA");
    }

    function test_FundsOnly_ReqPayloadIsEmpty() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.payload.length, 0, "FUNDS-only: req.payload must be empty");
    }

    // =========================================================================
    // 5) Value Semantics (Native vs ERC20)
    // =========================================================================

    function test_FundsAndPayload_Native_MsgValueForwardedCorrectly() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertEq(mockUniversalGateway.lastValue(), amount, "Native FUNDS_AND_PAYLOAD: msg.value should equal amount");
    }

    function test_FundsAndPayload_ERC20_MsgValueIsZero() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertEq(mockUniversalGateway.lastValue(), 0, "ERC20 FUNDS_AND_PAYLOAD: msg.value should be 0");
    }

    function test_FundsAndPayload_RevertWhen_SelfCallHasNonZeroValue() public deployCEA {
        fundCEAWithNative(10 ether);
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            1 ether, // Non-zero value to self-call
            buildSendToUEAPayloadWithData(address(0), 5 ether, ueaPayload)
        );

        vm.deal(vault, 1 ether);
        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx{value: 1 ether}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    // =========================================================================
    // 6) Approval / Allowance Behavior (ERC20 Path)
    // =========================================================================

    function test_FundsAndPayload_ERC20_SucceedsWithApproval() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "Should use viaCEA path");
    }

    function test_FundsAndPayload_ERC20_ApproveAndResetAllowance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](3);
        // Approve
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        // Send funds + payload
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );
        // Reset allowance to 0
        calls[2] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), 0)
        );

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)),
            0,
            "Allowance should be reset to 0"
        );
    }

    // =========================================================================
    // 7) Event Emission (CEA-Side)
    // =========================================================================

    function test_FundsAndPayload_EmitsUniversalTxToUEA_Native() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), amount, ueaPayload)
        );

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit UniversalTxToUEA(address(ceaInstance), ueaOnPush, address(0), amount);

        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    function test_FundsAndPayload_EmitsUniversalTxToUEA_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit UniversalTxToUEA(address(ceaInstance), ueaOnPush, address(token), amount);

        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );
    }

    // =========================================================================
    // 8) Failure Modes & Revert Surfacing
    // =========================================================================

    function test_FundsAndPayload_RevertWhen_GatewayReverts() public deployCEA {
        fundCEAWithNative(10 ether);
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        mockUniversalGateway.setWillRevert(true, "GatewayError");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), 5 ether, ueaPayload)
        );

        bytes32 txID = generateTxID(1);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID, generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertFalse(
            CEA(payable(address(ceaInstance))).isExecuted(txID),
            "txID should NOT be marked executed on gateway revert"
        );
    }

    function test_FundsAndPayload_MulticallRevert_NoPartialEffects() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        fundCEAWithNative(10 ether);

        Target payableTarget = new Target();
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        // Gateway reverts on second call
        mockUniversalGateway.setWillRevert(true, "GatewayError");

        Multicall[] memory calls = new Multicall[](2);
        // First call: set magic number (should succeed in isolation)
        calls[0] = makeCall(
            address(payableTarget), 0,
            abi.encodeWithSignature("setMagicNumber(uint256)", 42)
        );
        // Second call: sendUniversalTxToUEA with payload (gateway will revert)
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), 5 ether, ueaPayload)
        );

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        // Magic number should NOT be set because whole multicall reverted
        assertEq(payableTarget.getMagicNumber(), 0, "No partial effects on revert");
    }

    // =========================================================================
    // 9) End-to-End "CEA-only" Simulation (Using Mock Gateway)
    // =========================================================================

    function test_E2E_NativeFundsOnly() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = buildSelfSendToUEACall(address(0), amount);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID, universalTxID, ueaOnPush, encodeCalls(calls)
        );

        // Assertions
        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "FUNDS-only should use sendUniversalTxViaCEA");
        assertEq(mockUniversalGateway.lastValue(), amount, "msg.value should match amount");

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "recipient == UEA");
        assertEq(req.token, address(0), "token == address(0)");
        assertEq(req.amount, amount, "amount correct");
        assertEq(req.payload.length, 0, "payload empty");

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID marked executed");
        assertEq(address(ceaInstance).balance, 5 ether, "CEA balance decreased");
    }

    function test_E2E_ERC20FundsOnly() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = buildSelfSendToUEACall(address(token), amount);

        bytes32 txID = generateTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID, generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "FUNDS-only should use sendUniversalTxViaCEA");
        assertEq(mockUniversalGateway.lastValue(), 0, "msg.value should be 0 for ERC20");

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "recipient == UEA");
        assertEq(req.amount, amount, "amount correct");
        assertEq(req.payload.length, 0, "payload empty");
    }

    function test_E2E_NativeFundsAndPayload() public deployCEA {
        fundCEAWithNative(10 ether);
        uint256 amount = 5 ether;
        bytes memory ueaPayload = abi.encodeWithSignature("someFunction()");

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(0), amount, ueaPayload)
        );

        bytes32 txID = generateTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID, generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "FUNDS_AND_PAYLOAD should use sendUniversalTxViaCEA");
        assertEq(mockUniversalGateway.lastValue(), amount, "msg.value should match amount");

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "recipient == UEA");
        assertEq(req.amount, amount, "amount correct");
        assertEq(req.payload, ueaPayload, "payload matches");

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID marked executed");
        assertEq(address(ceaInstance).balance, 5 ether, "CEA balance decreased");
    }

    function test_E2E_ERC20FundsAndPayload() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        uint256 amount = 500 ether;
        bytes memory ueaPayload = hex"cafebabe";

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token), 0,
            abi.encodeWithSignature("approve(address,uint256)", address(mockUniversalGateway), amount)
        );
        calls[1] = makeCall(
            address(ceaInstance), 0,
            buildSendToUEAPayloadWithData(address(token), amount, ueaPayload)
        );

        bytes32 txID = generateTxID(1);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID, generateUniversalTxID(1), ueaOnPush, encodeCalls(calls)
        );

        assertTrue(mockUniversalGateway.lastCallWasViaCEA(), "FUNDS_AND_PAYLOAD should use sendUniversalTxViaCEA");
        assertEq(mockUniversalGateway.lastValue(), 0, "msg.value should be 0 for ERC20");

        UniversalTxRequest memory req = mockUniversalGateway.getLastRequest();
        assertEq(req.recipient, ueaOnPush, "recipient == UEA");
        assertEq(req.token, address(token), "token correct");
        assertEq(req.amount, amount, "amount correct");
        assertEq(req.payload, ueaPayload, "payload matches exact bytes");
    }

}
