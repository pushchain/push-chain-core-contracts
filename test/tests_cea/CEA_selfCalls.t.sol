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
    event WithdrawalToUEA(address indexed _cea, address indexed _uea, address indexed token, uint256 amount);

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
        calls[1] = buildSelfWithdrawCall(address(token), amount);

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
        calls[0] = buildSelfWithdrawCall(address(0), amount);

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
        calls[1] = buildSelfWithdrawCall(address(token), amount);

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
        calls[1] = buildSelfWithdrawCall(address(token), amount);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify revertInstruction.revertMsg == ""
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.revertInstruction.revertMsg, "", "RevertInstruction revertMsg should be empty");
    }

    // =========================================================================
    // 2) Event Emission Verification (payload/signatureData NOT in event)
    // =========================================================================

    function test_WithdrawalToUEAEvent_DoesNotContainPayload() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        bytes memory customPayload = abi.encode("custom data");
        bytes memory customSignature = abi.encode("signature data");

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "sendUniversalTxToUEA(address,uint256,bytes,bytes)",
                address(token),
                amount,
                customPayload,
                customSignature
            )
        );

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        // Event signature: WithdrawalToUEA(address indexed,address indexed,address indexed,uint256)
        // Does NOT include payload or signatureData for privacy/gas
        vm.expectEmit(true, true, true, true);
        emit WithdrawalToUEA(address(ceaInstance), ueaOnPush, address(token), amount);

        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

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
        calls[1] = buildSelfWithdrawCall(address(token), totalBalance);

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
        calls[0] = buildSelfWithdrawCall(address(0), totalBalance);

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
        calls[1] = buildSelfWithdrawCall(address(token), minAmount);

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
        calls[0] = buildSelfWithdrawCall(address(0), minAmount);

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
        // First withdrawal
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, 500 ether)
        );
        calls[1] = buildSelfWithdrawCall(address(token), 500 ether);

        // Second withdrawal
        calls[2] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, 300 ether)
        );
        calls[3] = buildSelfWithdrawCall(address(token), 300 ether);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify both calls went through
        assertEq(mockUniversalGateway.callCount(), 2, "Gateway should be called twice");
    }

    // =========================================================================
    // 6) Large Payload Parameter Tests
    // =========================================================================

    function test_SendUniversalTxToUEA_LargePayload_10KB() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        // Create 10KB payload
        bytes memory largePayload = new bytes(10 * 1024);
        for (uint i = 0; i < largePayload.length; i++) {
            largePayload[i] = bytes1(uint8(i % 256));
        }

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "sendUniversalTxToUEA(address,uint256,bytes,bytes)",
                address(token),
                amount,
                largePayload,
                ""
            )
        );

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify large payload was passed through correctly
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.payload.length, largePayload.length, "Payload length should match");
        assertEq(keccak256(lastReq.payload), keccak256(largePayload), "Payload content should match");
    }

    function test_SendUniversalTxToUEA_LargeSignatureData_10KB() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 txID = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;

        // Create 10KB signature data
        bytes memory largeSignature = new bytes(10 * 1024);
        for (uint i = 0; i < largeSignature.length; i++) {
            largeSignature[i] = bytes1(uint8(i % 256));
        }

        Multicall[] memory calls = new Multicall[](2);
        calls[0] = makeCall(
            address(token),
            0,
            abi.encodeWithSignature("approve(address,uint256)", universalGateway, amount)
        );
        calls[1] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "sendUniversalTxToUEA(address,uint256,bytes,bytes)",
                address(token),
                amount,
                "",
                largeSignature
            )
        );

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify large signature was passed through correctly
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.signatureData.length, largeSignature.length, "Signature length should match");
        assertEq(keccak256(lastReq.signatureData), keccak256(largeSignature), "Signature content should match");
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
        calls[1] = buildSelfWithdrawCall(address(0), 0.4 ether);

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
        calls[0] = buildSelfWithdrawCall(address(token), type(uint256).max);

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector); // Bubbled InsufficientBalance
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);
    }

    // =========================================================================
    // 9) Zero-Length vs Empty Bytes Tests
    // =========================================================================

    function test_SendUniversalTxToUEA_EmptyBytesPayloadAndSignature() public deployCEA {
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
        calls[1] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "sendUniversalTxToUEA(address,uint256,bytes,bytes)",
                address(token),
                amount,
                "",  // Empty bytes
                ""   // Empty bytes
            )
        );

        bytes memory payload = encodeCalls(calls);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(txID, universalTxID, ueaOnPush, payload);

        // Verify empty bytes are handled correctly
        UniversalTxRequest memory lastReq = mockUniversalGateway.getLastRequest();
        assertEq(lastReq.payload.length, 0, "Payload should be empty");
        assertEq(lastReq.signatureData.length, 0, "Signature should be empty");
    }
}
