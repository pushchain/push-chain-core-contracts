// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/cea/CEA.sol";
import "../../src/cea/CEAFactory.sol";
import {ICEAProxy} from "../../src/interfaces/ICEAProxy.sol";

// Import CEAProxy with explicit path to avoid Initializable conflict
// CEAProxy uses non-upgradeable Initializable, CEAFactory uses upgradeable
import {CEAProxy} from "../../src/cea/CEAProxy.sol";
import "../../src/interfaces/ICEA.sol";
import {IUniversalGateway, UniversalTxRequest} from "../../src/interfaces/IUniversalGateway.sol";
import {CEAErrors as Errors, CommonErrors} from "../../src/libraries/Errors.sol";
import {Multicall, MULTICALL_SELECTOR} from "../../src/libraries/Types.sol";
import {Target} from "../../src/mocks/Target.sol";
import {MockUniversalGateway} from "../mocks/MockUniversalGateway.sol";
import {MockGasToken} from "../mocks/MockGasToken.sol";
import {NonStandardERC20Token} from "../mocks/NonStandardERC20Token.sol";
import {MaliciousTarget} from "../mocks/MaliciousTarget.sol";
import {TokenReceiverTarget} from "../mocks/TokenReceiverTarget.sol";
import {TokenSpenderTarget} from "../mocks/TokenSpenderTarget.sol";
import {RevertingTarget} from "../mocks/RevertingTarget.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract CEATest is Test {
    // Core contracts
    CEA public ceaImplementation;
    CEAProxy public ceaProxyImplementation;
    CEAFactory public factory;
    ICEA public ceaInstance;

    // Mock contracts
    Target public target;
    MockUniversalGateway public mockUniversalGateway;

    // Test actors
    address public owner;
    address public vault;
    address public ueaOnPush;
    address public universalGateway;
    address public nonVault;

    // Constants
    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    function setUp() public {
        owner = address(this); // Test contract as owner
        vault = makeAddr("vault");
        ueaOnPush = makeAddr("ueaOnPush");
        universalGateway = makeAddr("universalGateway");
        nonVault = makeAddr("nonVault");

        target = new Target();
        mockUniversalGateway = new MockUniversalGateway();

        ceaImplementation = new CEA();

        ceaProxyImplementation = new CEAProxy();

        CEAFactory factoryImpl = new CEAFactory();

        bytes memory initData = abi.encodeWithSelector(
            CEAFactory.initialize.selector,
            owner,
            makeAddr("pauser"),
            vault,
            address(ceaProxyImplementation),
            address(ceaImplementation),
            address(mockUniversalGateway)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(factoryImpl), initData);
        factory = CEAFactory(address(proxy));
    }

    modifier deployCEA() {
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        ceaInstance = ICEA(ceaAddress);
        _;
    }

    // =========================================================================
    // Helper Functions - Canonical Multicall Builders
    // =========================================================================

    /// @notice Generate a unique subTxId for testing
    function generateTxID(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("subTxId", nonce));
    }

    /// @notice Generate a unique universalTxID for testing
    function generateUniversalTxID(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("universalTxID", nonce));
    }

    /// @notice Fund CEA with ERC20 tokens
    function fundCEAWithTokens(address token, uint256 amount) internal {
        MockGasToken(token).mint(address(ceaInstance), amount);
    }

    /// @notice Fund CEA with native tokens
    function fundCEAWithNative(uint256 amount) internal {
        vm.deal(address(ceaInstance), amount);
    }

    // -------------------------------------------------------------------------
    // Core Multicall Builders (align with new CEA model)
    // -------------------------------------------------------------------------

    /// @notice Create a single Multicall struct
    function makeCall(address to, uint256 value, bytes memory data) internal pure returns (Multicall memory) {
        return Multicall({to: to, value: value, data: data});
    }

    /// @notice Encode Multicall array into bytes payload
    function encodeCalls(Multicall[] memory calls) internal pure returns (bytes memory) {
        return abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));
    }

    /// @notice Build payload for sendUniversalTxToUEA self-call (funds only, empty payload)
    function buildSendToUEAPayload(address token, uint256 amount, address revertRecipient)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "sendUniversalTxToUEA(address,uint256,bytes,address)", token, amount, "", revertRecipient
        );
    }

    /// @notice Build payload for sendUniversalTxToUEA self-call with payload (FUNDS_AND_PAYLOAD)
    function buildSendToUEAPayloadWithData(address token, uint256 amount, bytes memory payload, address revertRecipient)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "sendUniversalTxToUEA(address,uint256,bytes,address)", token, amount, payload, revertRecipient
        );
    }

    /// @notice Build single external call payload (no approvals)
    function buildExternalSingleCall(address to, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(to, value, data);
        return encodeCalls(calls);
    }

    /// @notice Build external batch call payload
    function buildExternalBatch(Multicall[] memory calls) internal pure returns (bytes memory) {
        return encodeCalls(calls);
    }

    /// @notice Build self-call sendUniversalTxToUEA payload (single step, no approvals)
    /// @dev For ERC20, SDK must include approval steps separately. Defaults revertRecipient to pushAccount.
    function buildSelfSendToUEACall(address token, uint256 amount) internal view returns (Multicall memory) {
        return makeCall(address(ceaInstance), 0, buildSendToUEAPayload(token, amount, ueaOnPush));
    }

    /// @notice Build Multicall[] payload for ERC20 operations (with approval flow)
    /// @param token ERC20 token address
    /// @param target Target contract to call
    /// @param amount Amount to approve
    /// @param targetCalldata Calldata for target contract
    /// @return Encoded Multicall[] array
    function buildERC20MulticallPayload(address token, address target, uint256 amount, bytes memory targetCalldata)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[](3);

        // Step 1: Reset approval to 0
        calls[0] = Multicall({to: token, value: 0, data: abi.encodeWithSelector(IERC20.approve.selector, target, 0)});

        // Step 2: Approve amount
        calls[1] =
            Multicall({to: token, value: 0, data: abi.encodeWithSelector(IERC20.approve.selector, target, amount)});

        // Step 3: Execute target call
        calls[2] = Multicall({to: target, value: 0, data: targetCalldata});

        return encodeCalls(calls);
    }

    /// @notice Build Multicall[] payload for native token operations
    /// @param target Target contract to call
    /// @param value Native token value to send
    /// @param targetCalldata Calldata for target contract
    /// @return Encoded Multicall[] array
    function buildNativeMulticallPayload(address target, uint256 value, bytes memory targetCalldata)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[](1);

        calls[0] = Multicall({to: target, value: value, data: targetCalldata});

        return encodeCalls(calls);
    }

    /// @notice Build Multicall[] payload for self-call (sendUniversalTxToUEA)
    /// @param token Token address (address(0) for native)
    /// @param amount Amount to send
    /// @param approveGateway Whether to approve gateway for ERC20 (true for ERC20 sends)
    /// @return Encoded Multicall[] array
    function buildSendToUEAMulticallPayload(address token, uint256 amount, bool approveGateway)
        internal
        view
        returns (bytes memory)
    {
        if (!approveGateway || token == address(0)) {
            // Native token send or no approval needed
            Multicall[] memory calls = new Multicall[](1);
            calls[0] =
                Multicall({to: address(ceaInstance), value: 0, data: buildSendToUEAPayload(token, amount, ueaOnPush)});
            return encodeCalls(calls);
        } else {
            // ERC20 send with gateway approval
            Multicall[] memory calls = new Multicall[](3);

            // Step 1: Reset approval to gateway
            calls[0] = Multicall({
                to: token,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), 0)
            });

            // Step 2: Approve gateway for amount
            calls[1] = Multicall({
                to: token,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, address(mockUniversalGateway), amount)
            });

            // Step 3: Self-call to sendUniversalTxToUEA
            calls[2] =
                Multicall({to: address(ceaInstance), value: 0, data: buildSendToUEAPayload(token, amount, ueaOnPush)});

            return encodeCalls(calls);
        }
    }

    /// @notice Build simple Multicall[] payload with single external call (no approvals)
    /// @param target Target contract to call
    /// @param value Native token value to send
    /// @param targetCalldata Calldata for target contract
    /// @return Encoded Multicall[] array
    function buildSimpleMulticallPayload(address target, uint256 value, bytes memory targetCalldata)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({to: target, value: value, data: targetCalldata});
        return encodeCalls(calls);
    }

    // =========================================================================
    // Initialize and Setup Tests
    // =========================================================================

    function testInitializeCEA() public deployCEA {
        assertTrue(ceaInstance.isInitialized(), "CEA should be initialized");
        assertEq(ceaInstance.pushAccount(), ueaOnPush, "UEA should match");
        assertEq(ceaInstance.VAULT(), vault, "VAULT should match");

        // Verify event was emitted during deployment (factory calls initializeCEA)
        // Note: The event is emitted during factory.deployCEA, so we verify via state
        address cea = address(ceaInstance);
        assertEq(factory.getPushAccountForCEA(cea), ueaOnPush, "Factory mapping should be correct");
        (address returnedCEA, bool isDeployed) = factory.getCEAForPushAccount(ueaOnPush);
        assertEq(returnedCEA, cea, "Factory reverse mapping should be correct");
        assertTrue(isDeployed, "CEA should be marked as deployed");
    }

    function testRevertWhenInitializingTwice() public {
        CEA newCEA = new CEA();

        newCEA.initializeCEA(ueaOnPush, address(factory));

        vm.expectRevert(Errors.AlreadyInitialized.selector);
        newCEA.initializeCEA(ueaOnPush, address(factory));
    }

    function testRevertWhenInitializingWithZeroUEA() public {
        CEA newCEA = new CEA();

        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(address(0), address(factory));
    }

    function testRevertWhenInitializingWithZeroFactory() public {
        CEA newCEA = new CEA();

        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, address(0));
    }

    function testIsInitializedBeforeInitialization() public {
        CEA newCEA = new CEA();

        assertFalse(newCEA.isInitialized(), "CEA should not be initialized before initializeCEA is called");
    }

    function testFactoryDeployment() public {
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);

        assertTrue(factory.isCEA(ceaAddress), "Factory should recognize deployed CEA");
        assertEq(factory.getPushAccountForCEA(ceaAddress), ueaOnPush, "Factory should map CEA to UEA");
        (address mappedCEA, bool isDeployed) = factory.getCEAForPushAccount(ueaOnPush);
        assertEq(mappedCEA, ceaAddress, "Factory should map UEA to CEA");
        assertTrue(isDeployed, "Factory should mark CEA as deployed");
    }

    function testRevertWhenDeployingCEAAsNonVault() public {
        vm.prank(nonVault);
        vm.expectRevert();
        factory.deployCEA(ueaOnPush);
    }

    function testRevertWhenDeployingCEAWithZeroUEA() public {
        vm.prank(vault);
        vm.expectRevert();
        factory.deployCEA(address(0));
    }

    function testRevertWhenDeployingCEATwice() public {
        vm.prank(vault);
        factory.deployCEA(ueaOnPush);

        vm.prank(vault);
        vm.expectRevert();
        factory.deployCEA(ueaOnPush);
    }

    // =========================================================================
    // executeUniversalTx Tests - ERC20 Token Version
    // =========================================================================

    function testExecuteUniversalTx_RevertWhenCalledByNonVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory targetCalldata = abi.encodeWithSignature("setMagicNumber(uint256)", 42);
        bytes memory payload = buildERC20MulticallPayload(address(token), address(target), 100 ether, targetCalldata);

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), payload);
    }

    function testExecuteUniversalTx_SuccessWhenCalledByVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory targetCalldata = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);
        bytes memory payload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, targetCalldata);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), payload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(spender.totalReceived(address(token)), 100 ether, "Target should receive tokens");
    }

    // -------------------------------------------------------------------------
    // 2. REENTRANCY PROTECTION TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_RevertWhenTxIDAlreadyExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory targetCalldata = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);
        bytes memory payload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, targetCalldata);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), payload);

        // Try to execute same subTxId again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), payload);
    }

    // -------------------------------------------------------------------------
    // 4. PARAMETER VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_RevertWhenInvalidUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(target), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, makeAddr("wrongUEA"), address(0), multicallPayload);
    }

    function testExecuteUniversalTx_RevertWhenTargetIsZero() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidTarget.selector);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(0), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testExecuteUniversalTx_SuccessWithSufficientTokenBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(spender.totalReceived(address(token)), 100 ether, "Exact balance should work");
    }

    // -------------------------------------------------------------------------
    // 6. ERC20 TOKEN APPROVAL PATTERN TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_ResetsApprovalBeforeGranting() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();

        // Set an existing approval
        vm.prank(address(ceaInstance));
        token.approve(address(spender), 500 ether);
        assertEq(token.allowance(address(ceaInstance), address(spender)), 500 ether, "Initial approval should exist");

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Approval should be reset to 0 after execution
        assertEq(token.allowance(address(ceaInstance), address(spender)), 0, "Approval should be reset");
    }

    function testExecuteUniversalTx_GrantsCorrectApprovalAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        // We can't directly check intermediate approval state, but we verify execution succeeds
        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(spender.totalReceived(address(token)), 100 ether, "Correct amount should be approved and spent");
    }

    function testExecuteUniversalTx_ResetsApprovalAfterExecution() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Approval should be reset to 0 after execution
        assertEq(token.allowance(address(ceaInstance), address(spender)), 0, "Approval should be reset after execution");
    }

    function testExecuteUniversalTx_TokenRevertsOnZeroApproval() public deployCEA {
        NonStandardERC20Token token = new NonStandardERC20Token("NonStdToken", "NST", 18);
        fundCEAWithTokens(address(token), 1000 ether);

        // Set an existing approval first
        vm.prank(address(ceaInstance));
        token.approve(address(target), 500 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        // This should still work - resetApproval handles the revert gracefully
        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(
            spender.totalReceived(address(token)), 100 ether, "Execution should succeed despite zero approval revert"
        );
    }

    // -------------------------------------------------------------------------
    // 7. EXECUTION CALL TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_SuccessfulCallToTarget() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(target), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(target.getMagicNumber(), 42, "Target should execute correctly");
    }

    function testExecuteUniversalTx_TargetReceivesCorrectTokenAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenReceiverTarget receiver = new TokenReceiverTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("receiveTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload =
            buildERC20MulticallPayload(address(token), address(receiver), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(receiver.tokenBalances(address(token)), 100 ether, "Target should receive correct amount");
        assertEq(MockGasToken(token).balanceOf(address(receiver)), 100 ether, "Balance should be correct");
    }

    function testExecuteUniversalTx_RevertWhenTargetReverts() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        RevertingTarget reverter = new RevertingTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        vm.prank(vault);
        bytes memory multicallPayload =
            buildERC20MulticallPayload(address(token), address(reverter), 100 ether, payload);

        // Underlying revert reason is now propagated
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // subTxId should NOT be marked as executed when execution fails
        assertFalse(
            CEA(payable(address(ceaInstance))).isExecuted(subTxId),
            "subTxId should not be marked as executed on failure"
        );
    }

    function testExecuteUniversalTx_SuccessWithEmptyPayload() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = ""; // Empty payload

        // Note: With empty payload, tokens are still approved and can be spent
        // Note: But we need a target that can receive them
        bytes memory spendPayload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload =
            buildERC20MulticallPayload(address(token), address(spender), 100 ether, spendPayload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(spender.totalReceived(address(token)), 100 ether, "Empty payload should work");
    }

    function testExecuteUniversalTx_ExecutesPayloadCorrectly() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 magicValue = 999;
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", magicValue);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(target), 100 ether, payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(target.getMagicNumber(), magicValue, "Payload should execute with correct parameters");
    }

    // =========================================================================
    // executeUniversalTx Tests - Native Token Version
    // =========================================================================

    function testExecuteUniversalTx_RevertWhenCalledByNonVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(nonVault);
        vm.deal(nonVault, 0.1 ether);
        vm.expectRevert(Errors.NotVault.selector);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), 0.1 ether, payload);

        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            subTxId, universalTxID, ueaOnPush, address(0), multicallPayload
        );
    }

    function testExecuteUniversalTx_RevertWhenInvalidUEA_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        vm.expectRevert(Errors.InvalidUEA.selector);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), 0.1 ether, payload);

        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            subTxId, universalTxID, makeAddr("wrongUEA"), address(0), multicallPayload
        );
    }

    function testExecuteUniversalTx_MsgValueExceedsCallValue_Native_Succeeds() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.2 ether);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), 0.1 ether, payload);

        // Excess msg.value stays in CEA — no strict equality check
        ceaInstance.executeUniversalTx{value: 0.2 ether}(
            subTxId, universalTxID, ueaOnPush, address(0), multicallPayload
        );

        assertEq(target.getMagicNumber(), 42, "Target should execute correctly");
    }

    function testExecuteUniversalTx_SuccessWhenMsgValueEqualsAmount_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);
        uint256 amount = 0.1 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), amount, payload);

        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(address(target).balance, amount, "Target should receive correct amount");
    }

    // Note: Native token balance check doesn't apply here because:
    // - Validation only checks msg.value == amount for native tokens
    // - The CEA receives msg.value, so balance is always sufficient
    // - Insufficient balance only matters for self-calls (sendUniversalTxToUEA)

    function testExecuteUniversalTx_SuccessfulCallToTarget_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), 0.1 ether, payload);

        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            subTxId, universalTxID, ueaOnPush, address(0), multicallPayload
        );

        assertEq(target.getMagicNumber(), 42, "Target should execute correctly");
        assertEq(address(target).balance, 0.1 ether, "Target should receive native tokens");
    }

    function testExecuteUniversalTx_TargetReceivesCorrectNativeAmount() public deployCEA {
        fundCEAWithNative(1000 ether);

        TokenReceiverTarget receiver = new TokenReceiverTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("receiveNative()");
        uint256 amount = 0.5 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(receiver), amount, payload);

        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(receiver.nativeBalance(), amount, "Target should receive correct native amount");
    }

    function testExecuteUniversalTx_RevertWhenTargetReverts_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        RevertingTarget reverter = new RevertingTarget();
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(reverter), 0.1 ether, payload);

        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            subTxId, universalTxID, ueaOnPush, address(0), multicallPayload
        );
    }

    // =========================================================================
    // Event Emission Tests
    // =========================================================================

    function testExecuteUniversalTx_EmitsUniversalTxExecutedEvent() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(target), 100 ether, payload);

        // Note: Event is emitted per multicall step (3 events: reset approval, approve, execute)
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(target), payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testExecuteUniversalTx_EmitsUniversalTxExecutedEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);
        uint256 amount = 0.1 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(target), amount, payload);

        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(target), payload);

        ceaInstance.executeUniversalTx{value: amount}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }
    // -------------------------------------------------------------------------
    // 1. ACCESS CONTROL & AUTHORIZATION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_RevertWhenCalledByNonVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_SuccessWhenCalledByVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    // -------------------------------------------------------------------------
    // 2. _handleSelfCalls VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_RevertWhenTxIDAlreadyExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Try to execute same subTxId again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenInvalidUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, makeAddr("wrongUEA"), address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenPayloadTooShort() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Create multicall with malformed self-call data (too short)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(ceaInstance), 0, "123"); // Only 3 bytes
        bytes memory multicallPayload = encodeCalls(calls);

        vm.prank(vault);
        // After removing _handleSelfCall, malformed calls execute via .call() and fail
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenInvalidSelector() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Create multicall with wrong selector (try to call initializeCEA)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "initializeCEA(address,address)", address(0), address(0)
            )
        );
        bytes memory multicallPayload = encodeCalls(calls);

        vm.prank(vault);
        // Calls initializeCEA via .call() which reverts with AlreadyInitialized
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    // -------------------------------------------------------------------------
    // 3. BALANCE VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_RevertWhenInsufficientERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_SuccessWithExactERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 500 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testSendUniversalTxToUEA_SuccessWithMoreThanRequiredBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
    }

    // -------------------------------------------------------------------------
    // 4. UNIVERSAL GATEWAY INTERACTION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_CallsGatewayWithCorrectParams_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), amount, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), amount, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(token), "Token should match");
        assertEq(mockUniversalGateway.lastAmount(), amount, "Amount should match");
        assertEq(mockUniversalGateway.lastPayload().length, 0, "Payload should be empty");
        assertEq(mockUniversalGateway.lastFundRecipient(), ueaOnPush, "Fund recipient should be UEA");
        assertEq(mockUniversalGateway.lastSignatureData().length, 0, "Signature data should be empty");
        assertEq(mockUniversalGateway.lastValue(), 0, "No native value should be sent");
    }

    function testSendUniversalTxToUEA_CallsGatewayExactlyOnce_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        uint256 callCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.callCount(), callCountBefore + 1, "Gateway should be called exactly once");
    }

    // -------------------------------------------------------------------------
    // 5. ERC20 APPROVAL PATTERN TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_ResetsApprovalBeforeGranting() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        // Set an existing approval to gateway
        vm.prank(address(ceaInstance));
        token.approve(address(mockUniversalGateway), 300 ether);
        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)),
            300 ether,
            "Initial approval should exist"
        );

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Approval persists after gateway call (gateway consumes via transferFrom in production)
        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)),
            500 ether,
            "Approval should persist (mock gateway doesn't consume)"
        );
    }

    function testSendUniversalTxToUEA_GrantsCorrectApprovalAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), amount, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), amount, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Approval persists after gateway call (mock gateway doesn't consume)
        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)), amount, "Approval should persist"
        );
    }

    // -------------------------------------------------------------------------
    // 6. STATE CHANGES TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_MarksTxIDAsExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(token), 500 ether, ueaOnPush);

        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should not be executed before");

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 500 ether, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed after");
    }

    function testSendUniversalTxToUEA_ERC20BalanceDecreases() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 initialBalance = 1000 ether;
        fundCEAWithTokens(address(token), initialBalance);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 sendAmount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), sendAmount, ueaOnPush);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), sendAmount, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Mock gateway doesn't transfer tokens, so balance unchanged
        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, balanceBefore, "Balance should remain same (mock doesn't transfer)");
        // Approval persists after gateway call (mock gateway doesn't consume)
        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)), sendAmount, "Approval should persist"
        );
    }

    // -------------------------------------------------------------------------
    // 7. EVENT EMISSION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_EmitsUniversalTxToUEAEvent_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), amount, ueaOnPush);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxToUEA(address(ceaInstance), ueaOnPush, address(token), amount);

        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), amount, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_EmitsUniversalTxExecutedEvent_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), amount, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), amount, true);

        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(ceaInstance), payload);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    // -------------------------------------------------------------------------
    // 8. EDGE CASES & SECURITY TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_HandlesZeroAmount_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), 0, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.lastAmount(), 0, "Should allow zero amount for ERC20");
    }

    function testSendUniversalTxToUEA_MultipleSendsWithDifferentTxIDs_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 2000 ether);

        uint256 amount = 500 ether;

        for (uint256 i = 1; i <= 3; i++) {
            bytes32 subTxId = generateTxID(i);
            bytes32 universalTxID = generateUniversalTxID(i);
            bytes memory payload = buildSendToUEAPayload(address(token), amount, ueaOnPush);

            vm.prank(vault);
            bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), amount, true);

            ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

            assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        }

        assertEq(mockUniversalGateway.callCount(), 3, "Gateway should be called 3 times");
    }

    // -------------------------------------------------------------------------
    // 9. INTEGRATION TESTS
    // -------------------------------------------------------------------------

    function testSendUniversalTxToUEA_FullFlow_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 initialBalance = 1000 ether;
        fundCEAWithTokens(address(token), initialBalance);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 sendAmount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(token), sendAmount, ueaOnPush);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));
        uint256 gatewayCallCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(token), sendAmount, true);

        ceaInstance.executeUniversalTx(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Verify all state changes
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), gatewayCallCountBefore + 1, "Gateway should be called once");

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(token), "Token should match");
        assertEq(mockUniversalGateway.lastAmount(), sendAmount, "Amount should match");

        // Mock gateway doesn't transfer tokens, so balance unchanged
        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, balanceBefore, "Balance should remain same (mock doesn't transfer)");
        // Approval persists after gateway call (mock gateway doesn't consume)
        assertEq(
            token.allowance(address(ceaInstance), address(mockUniversalGateway)), sendAmount, "Approval should persist"
        );
    }

    // =========================================================================
    // sendUniversalTxToUEA Tests - Native Token Version
    // =========================================================================

    function testSendUniversalTxToUEA_RevertWhenCalledByNonVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(nonVault);
        vm.deal(nonVault, 0.1 ether);
        vm.expectRevert(Errors.NotVault.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_SuccessWhenCalledByVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testSendUniversalTxToUEA_RevertWhenTxIDAlreadyExecuted_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Try to execute same subTxId again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenInvalidUEA_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(
            subTxId, universalTxID, makeAddr("wrongUEA"), address(0), multicallPayload
        );
    }

    function testSendUniversalTxToUEA_RevertWhenPayloadTooShort_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Create multicall with malformed self-call data (too short)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(address(ceaInstance), 0, "123"); // Only 3 bytes
        bytes memory multicallPayload = encodeCalls(calls);

        vm.prank(vault);
        // After removing _handleSelfCall, malformed calls execute via .call() and fail
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenInvalidSelector_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        // Create multicall with wrong selector (try to call initializeCEA)
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = makeCall(
            address(ceaInstance),
            0,
            abi.encodeWithSignature(
                "initializeCEA(address,address)", address(0), address(0)
            )
        );
        bytes memory multicallPayload = encodeCalls(calls);

        vm.prank(vault);
        // Calls initializeCEA via .call() which reverts with AlreadyInitialized
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_RevertWhenInsufficientNativeBalance() public deployCEA {
        // Don't fund CEA
        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_SuccessWithExactNativeBalance() public deployCEA {
        uint256 balance = 500 ether;
        fundCEAWithNative(balance);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), balance, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), balance, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testSendUniversalTxToUEA_SuccessWithMoreThanRequiredBalance_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
    }

    function testSendUniversalTxToUEA_CallsGatewayWithCorrectParams_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(0), amount, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), amount, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(0), "Token should be address(0) for native");
        assertEq(mockUniversalGateway.lastAmount(), amount, "Amount should match");
        assertEq(mockUniversalGateway.lastPayload().length, 0, "Payload should be empty");
        assertEq(mockUniversalGateway.lastFundRecipient(), ueaOnPush, "Fund recipient should be UEA");
        assertEq(mockUniversalGateway.lastValue(), amount, "Native value should match amount");
    }

    function testSendUniversalTxToUEA_CallsGatewayExactlyOnce_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        uint256 callCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.callCount(), callCountBefore + 1, "Gateway should be called exactly once");
    }

    function testSendUniversalTxToUEA_MarksTxIDAsExecuted_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should not be executed before");

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed after");
    }

    function testSendUniversalTxToUEA_NativeBalanceDecreases() public deployCEA {
        uint256 initialBalance = 1000 ether;
        fundCEAWithNative(initialBalance);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 sendAmount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(0), sendAmount, ueaOnPush);

        uint256 balanceBefore = address(ceaInstance).balance;

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), sendAmount, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, balanceBefore - sendAmount, "Balance should decrease by exact amount");
        assertEq(mockUniversalGateway.lastValue(), sendAmount, "Gateway should receive correct value");
    }

    function testSendUniversalTxToUEA_EmitsUniversalTxToUEAEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(0), amount, ueaOnPush);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxToUEA(address(ceaInstance), ueaOnPush, address(0), amount);

        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), amount, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_EmitsUniversalTxExecutedEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(0), amount, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), amount, false);

        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(subTxId, universalTxID, ueaOnPush, address(ceaInstance), payload);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);
    }

    function testSendUniversalTxToUEA_HandlesZeroAmount_Native() public deployCEA {
        fundCEAWithNative(1000 ether);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 0, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        assertEq(mockUniversalGateway.lastAmount(), 0, "Should allow zero amount for native");
    }

    function testSendUniversalTxToUEA_MultipleSendsWithDifferentTxIDs_Native() public deployCEA {
        fundCEAWithNative(2000 ether);

        uint256 amount = 500 ether;

        for (uint256 i = 1; i <= 3; i++) {
            bytes32 subTxId = generateTxID(i);
            bytes32 universalTxID = generateUniversalTxID(i);
            bytes memory payload = buildSendToUEAPayload(address(0), amount, ueaOnPush);

            vm.prank(vault);
            bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), amount, false);

            ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

            assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        }

        assertEq(mockUniversalGateway.callCount(), 3, "Gateway should be called 3 times");
    }

    function testSendUniversalTxToUEA_FullFlow_Native() public deployCEA {
        uint256 initialBalance = 1000 ether;
        fundCEAWithNative(initialBalance);

        bytes32 subTxId = generateTxID(1);
        bytes32 universalTxID = generateUniversalTxID(1);
        uint256 sendAmount = 500 ether;
        bytes memory payload = buildSendToUEAPayload(address(0), sendAmount, ueaOnPush);

        uint256 balanceBefore = address(ceaInstance).balance;
        uint256 gatewayCallCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), sendAmount, false);

        ceaInstance.executeUniversalTx{value: 0}(subTxId, universalTxID, ueaOnPush, address(0), multicallPayload);

        // Verify all state changes
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), gatewayCallCountBefore + 1, "Gateway should be called once");

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(0), "Token should be address(0) for native");
        assertEq(mockUniversalGateway.lastAmount(), sendAmount, "Amount should match");
        assertEq(mockUniversalGateway.lastValue(), sendAmount, "Gateway should receive correct value");

        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, balanceBefore - sendAmount, "Balance should decrease");
    }

    // =========================================================================
    // executeUniversalTx ERC20 Gap Tests
    // =========================================================================

    function testExecuteUniversalTx_ERC20_MsgValueNonZero_ExcessStaysInCEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        vm.deal(vault, 1 ether);

        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        bytes memory multicallPayload = buildERC20MulticallPayload(address(token), address(spender), 100 ether, payload);

        uint256 ceaBalanceBefore = address(ceaInstance).balance;

        ceaInstance.executeUniversalTx{value: 1 ether}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), multicallPayload
        );

        // Excess ETH stays in CEA
        assertEq(address(ceaInstance).balance, ceaBalanceBefore + 1 ether, "Excess msg.value stays in CEA");
    }

    function testExecuteUniversalTx_ERC20_AllowanceRemainsZeroAfterRevert() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);

        RevertingTarget reverter = new RevertingTarget();
        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        uint256 allowanceBefore = token.allowance(address(ceaInstance), address(reverter));

        vm.prank(vault);
        bytes memory multicallPayload =
            buildERC20MulticallPayload(address(token), address(reverter), 100 ether, payload);

        // Underlying revert reason is now propagated
        vm.expectRevert("This function always reverts with reason");
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), multicallPayload
        );

        // Whole tx reverts so allowance is unchanged (stays at 0)
        assertEq(
            token.allowance(address(ceaInstance), address(reverter)),
            allowanceBefore,
            "Allowance should revert to original"
        );
    }

    // =========================================================================
    // executeUniversalTx Native Gap Tests
    // =========================================================================

    function testExecuteUniversalTx_Native_RevertWhenTargetHasNoReceive() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();
        uint256 amount = 0.1 ether;
        vm.deal(vault, amount);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(reverter), amount, bytes(""));

        ceaInstance.executeUniversalTx{value: amount}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), multicallPayload
        );
    }

    function testExecuteUniversalTx_Native_IsExecutedOnlyOnSuccess() public deployCEA {
        RevertingTarget reverter = new RevertingTarget();
        uint256 amount = 0.1 ether;
        bytes32 subTxId = generateTxID(1);
        vm.deal(vault, amount);

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        bytes memory multicallPayload = buildNativeMulticallPayload(address(reverter), amount, bytes(""));

        ceaInstance.executeUniversalTx{value: amount}(
            subTxId, generateUniversalTxID(1), ueaOnPush, address(0), multicallPayload
        );

        assertFalse(
            CEA(payable(address(ceaInstance))).isExecuted(subTxId), "subTxId should not be marked executed on failure"
        );
    }

    // =========================================================================
    // Self-call (_handleSelfCalls) Edge Case Tests
    // =========================================================================

    function testHandleSelfCalls_AcceptsValueWithSelfCall() public deployCEA {
        // Fund CEA with native, execute self-call sendUniversalTxToUEA
        fundCEAWithNative(500 ether);

        bytes memory payload = buildSendToUEAPayload(address(0), 500 ether, ueaOnPush);

        vm.prank(vault);
        bytes memory multicallPayload = buildSendToUEAMulticallPayload(address(0), 500 ether, false);

        // Note: msg.value must match total multicall values (0 in this case, as self-call doesn't need value)
        ceaInstance.executeUniversalTx{value: 0}(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), multicallPayload
        );

        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testHandleSelfCalls_RevertWhenPayloadExactly4Bytes() public deployCEA {
        fundCEAWithNative(100 ether);

        // Exactly 4 bytes (selector only) — abi.decode on empty payload[4:] will panic
        bytes memory selectorOnly =
            abi.encodePacked(bytes4(keccak256("sendUniversalTxToUEA(address,uint256,bytes,address)")));

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({to: address(ceaInstance), value: 0, data: selectorOnly});

        vm.prank(vault);
        vm.expectRevert();
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), encodeCalls(calls)
        );
    }

    function testHandleSelfCalls_RevertWhenArgsAreMalformed() public deployCEA {
        fundCEAWithNative(100 ether);

        // Correct selector but truncated args
        bytes4 selector = bytes4(keccak256("sendUniversalTxToUEA(address,uint256,bytes,address)"));
        bytes memory malformed = abi.encodePacked(selector, bytes28(0));

        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({to: address(ceaInstance), value: 0, data: malformed});

        vm.prank(vault);
        vm.expectRevert();
        ceaInstance.executeUniversalTx(
            generateTxID(1), generateUniversalTxID(1), ueaOnPush, address(0), encodeCalls(calls)
        );
    }

    // =========================================================================
    // General Invariants / Misc
    // =========================================================================

    function testInitializeCEA_CannotBeCalledAgainAfterProxyDeployment() public deployCEA {
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        CEA(payable(address(ceaInstance)))
            .initializeCEA(ueaOnPush, address(factory));
    }

    function testReceive_DirectETHTransferSucceeds() public deployCEA {
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        uint256 balanceBefore = address(ceaInstance).balance;
        (bool success,) = address(ceaInstance).call{value: amount}("");
        assertTrue(success, "Direct ETH transfer should succeed");
        assertEq(address(ceaInstance).balance, balanceBefore + amount, "CEA balance should increase");
    }

    // =========================================================================
    // CEAProxy Branch Coverage
    // =========================================================================

    function testCEAProxy_InitializeWithZeroLogic_Reverts() public {
        CEAProxy proxy = new CEAProxy();
        vm.expectRevert(Errors.InvalidCall.selector);
        proxy.initializeCEAProxy(address(0));
    }

    function testCEAProxy_InitializeWhenAlreadySet_Reverts() public deployCEA {
        // ceaInstance is already initialized via deployCEA modifier
        // Attempt to re-initialize the proxy directly
        // The Initializable guard will revert before the currentImpl check
        vm.expectRevert();
        CEAProxy(payable(address(ceaInstance))).initializeCEAProxy(address(ceaImplementation));
    }

    function testCEAProxy_CallBeforeInit_Reverts() public {
        // Deploy a raw CEAProxy clone (not initialized)
        address rawClone = address(new CEAProxy());
        // Any call to the uninitialized proxy should revert
        // because _implementation() reverts when impl == address(0)
        vm.expectRevert(Errors.InvalidCall.selector);
        CEA(payable(rawClone)).pushAccount();
    }
}

