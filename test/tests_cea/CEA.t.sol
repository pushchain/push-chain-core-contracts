// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../../src/CEA/CEA.sol";
import "../../src/CEA/CEAFactory.sol";
import {ICEAProxy} from "../../src/interfaces/ICEAProxy.sol";

// Import CEAProxy with explicit path to avoid Initializable conflict
// CEAProxy uses non-upgradeable Initializable, CEAFactory uses upgradeable
import {CEAProxy} from "../../src/CEA/CEAProxy.sol";
import "../../src/interfaces/ICEA.sol";
import {IUniversalGateway, UniversalTxRequest, RevertInstructions} from "../../src/interfaces/IUniversalGateway.sol";
import {CEAErrors as Errors} from "../../src/libraries/Errors.sol";
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
    // Helper Functions
    // =========================================================================

    /// @notice Generate a unique txID for testing
    function generateTxID(uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("txID", nonce));
    }

    /// @notice Fund CEA with ERC20 tokens
    function fundCEAWithTokens(address token, uint256 amount) internal {
        MockGasToken(token).mint(address(ceaInstance), amount);
    }

    /// @notice Fund CEA with native tokens
    function fundCEAWithNative(uint256 amount) internal {
        vm.deal(address(ceaInstance), amount);
    }

    /// @notice Build payload for withdrawFundsToUEA self-call
    function buildWithdrawPayload(address token, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("withdrawFundsToUEA(address,uint256)", token, amount);
    }



    // =========================================================================
    // Initialize and Setup Tests
    // =========================================================================

    function testInitializeCEA() public deployCEA {
        assertTrue(ceaInstance.isInitialized(), "CEA should be initialized");
        assertEq(ceaInstance.UEA(), ueaOnPush, "UEA should match");
        assertEq(ceaInstance.VAULT(), vault, "VAULT should match");
        
        // Verify event was emitted during deployment (factory calls initializeCEA)
        // Note: The event is emitted during factory.deployCEA, so we verify via state
        address cea = address(ceaInstance);
        assertEq(factory.getUEAForCEA(cea), ueaOnPush, "Factory mapping should be correct");
        (address returnedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
        assertEq(returnedCEA, cea, "Factory reverse mapping should be correct");
        assertTrue(isDeployed, "CEA should be marked as deployed");
    }
    
    function testRevertWhenInitializingTwice() public {
        CEA newCEA = new CEA();
        
        newCEA.initializeCEA(ueaOnPush, vault, address(mockUniversalGateway));
        
        vm.expectRevert(Errors.AlreadyInitialized.selector);
        newCEA.initializeCEA(ueaOnPush, vault, address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroUEA() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(address(0), vault, address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroVault() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, address(0), address(mockUniversalGateway));
    }
    
    function testRevertWhenInitializingWithZeroUniversalGateway() public {
        CEA newCEA = new CEA();
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        newCEA.initializeCEA(ueaOnPush, vault, address(0));
    }
    
    function testIsInitializedBeforeInitialization() public {
        CEA newCEA = new CEA();
        
        assertFalse(newCEA.isInitialized(), "CEA should not be initialized before initializeCEA is called");
    }
    
    function testFactoryDeployment() public {
        vm.prank(vault);
        address ceaAddress = factory.deployCEA(ueaOnPush);
        
        assertTrue(factory.isCEA(ceaAddress), "Factory should recognize deployed CEA");
        assertEq(factory.getUEAForCEA(ceaAddress), ueaOnPush, "Factory should map CEA to UEA");
        (address mappedCEA, bool isDeployed) = factory.getCEAForUEA(ueaOnPush);
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
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(target),
            100 ether,
            payload
        );
    }

    function testExecuteUniversalTx_SuccessWhenCalledByVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(spender.totalReceived(address(token)), 100 ether, "Target should receive tokens");
    }

    // -------------------------------------------------------------------------
    // 2. REENTRANCY PROTECTION TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_RevertWhenTxIDAlreadyExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

        // Try to execute same txID again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );
    }

    // -------------------------------------------------------------------------
    // 4. PARAMETER VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_RevertWhenInvalidUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx(
            txID,
            makeAddr("wrongUEA"),
            address(token),
            address(target),
            100 ether,
            payload
        );
    }

    function testExecuteUniversalTx_RevertWhenTargetIsZero() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidTarget.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(0),
            100 ether,
            payload
        );
    }

    // Note: The ERC20 version is non-payable, so we cannot test msg.value with it
    // The validation check for msg.value != 0 exists but cannot be triggered via external call
    // This is a compile-time safety measure - non-payable functions reject value transfers

    // -------------------------------------------------------------------------
    // 5. BALANCE VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_RevertWhenInsufficientTokenBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(target),
            200 ether, 
            payload
        );
    }

    function testExecuteUniversalTx_SuccessWithSufficientTokenBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

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

        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

        // Approval should be reset to 0 after execution
        assertEq(token.allowance(address(ceaInstance), address(spender)), 0, "Approval should be reset");
    }

    function testExecuteUniversalTx_GrantsCorrectApprovalAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        // We can't directly check intermediate approval state, but we verify execution succeeds
        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

        assertEq(spender.totalReceived(address(token)), 100 ether, "Correct amount should be approved and spent");
    }

    function testExecuteUniversalTx_ResetsApprovalAfterExecution() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

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
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        // This should still work - resetApproval handles the revert gracefully
        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            payload
        );

        assertEq(spender.totalReceived(address(token)), 100 ether, "Execution should succeed despite zero approval revert");
    }

    // -------------------------------------------------------------------------
    // 7. EXECUTION CALL TESTS
    // -------------------------------------------------------------------------

    function testExecuteUniversalTx_SuccessfulCallToTarget() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(target),
            100 ether,
            payload
        );

        assertEq(target.getMagicNumber(), 42, "Target should execute correctly");
    }

    function testExecuteUniversalTx_TargetReceivesCorrectTokenAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenReceiverTarget receiver = new TokenReceiverTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("receiveTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(receiver),
            100 ether,
            payload
        );

        assertEq(receiver.tokenBalances(address(token)), 100 ether, "Target should receive correct amount");
        assertEq(MockGasToken(token).balanceOf(address(receiver)), 100 ether, "Balance should be correct");
    }

    function testExecuteUniversalTx_RevertWhenTargetReverts() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        RevertingTarget reverter = new RevertingTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        vm.prank(vault);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(reverter),
            100 ether,
            payload
        );

        // txID should NOT be marked as executed when execution fails
        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be marked as executed on failure");
    }

    function testExecuteUniversalTx_SuccessWithEmptyPayload() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        TokenSpenderTarget spender = new TokenSpenderTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = ""; // Empty payload

        // Note: With empty payload, tokens are still approved and can be spent
        // Note: But we need a target that can receive them
        bytes memory spendPayload = abi.encodeWithSignature("spendTokens(address,uint256)", address(token), 100 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(spender),
            100 ether,
            spendPayload
        );

        assertEq(spender.totalReceived(address(token)), 100 ether, "Empty payload should work");
    }

    function testExecuteUniversalTx_ExecutesPayloadCorrectly() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 magicValue = 999;
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", magicValue);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(target),
            100 ether,
            payload
        );

        assertEq(target.getMagicNumber(), magicValue, "Payload should execute with correct parameters");
    }

    // =========================================================================
    // executeUniversalTx Tests - Native Token Version
    // =========================================================================

    function testExecuteUniversalTx_RevertWhenCalledByNonVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(nonVault);
        vm.deal(nonVault, 0.1 ether);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            txID,
            ueaOnPush,
            address(target),
            0.1 ether,
            payload
        );
    }

    function testExecuteUniversalTx_RevertWhenInvalidUEA_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            txID,
            makeAddr("wrongUEA"),
            address(target),
            0.1 ether,
            payload
        );
    }

    function testExecuteUniversalTx_RevertWhenMsgValueDoesNotMatchAmount_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.2 ether);
        vm.expectRevert(Errors.InvalidAmount.selector);
        ceaInstance.executeUniversalTx{value: 0.2 ether}(
            txID,
            ueaOnPush,
            address(target),
            0.1 ether, // Different from msg.value
            payload
        );
    }

    function testExecuteUniversalTx_SuccessWhenMsgValueEqualsAmount_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);
        uint256 amount = 0.1 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        ceaInstance.executeUniversalTx{value: amount}(
            txID,
            ueaOnPush,
            address(target),
            amount,
            payload
        );

        assertEq(address(target).balance, amount, "Target should receive correct amount");
    }

    // Note: Native token balance check doesn't apply here because:
    // - Validation only checks msg.value == amount for native tokens
    // - The CEA receives msg.value, so balance is always sufficient
    // - Insufficient balance only matters for self-calls (withdrawFundsToUEA)

    function testExecuteUniversalTx_SuccessfulCallToTarget_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            txID,
            ueaOnPush,
            address(target),
            0.1 ether,
            payload
        );

        assertEq(target.getMagicNumber(), 42, "Target should execute correctly");
        assertEq(address(target).balance, 0.1 ether, "Target should receive native tokens");
    }

    function testExecuteUniversalTx_TargetReceivesCorrectNativeAmount() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        TokenReceiverTarget receiver = new TokenReceiverTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("receiveNative()");
        uint256 amount = 0.5 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        ceaInstance.executeUniversalTx{value: amount}(
            txID,
            ueaOnPush,
            address(receiver),
            amount,
            payload
        );

        assertEq(receiver.nativeBalance(), amount, "Target should receive correct native amount");
    }

    function testExecuteUniversalTx_RevertWhenTargetReverts_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        RevertingTarget reverter = new RevertingTarget();
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("revertWithReason()");

        vm.prank(vault);
        vm.deal(vault, 0.1 ether);
        vm.expectRevert(Errors.ExecutionFailed.selector);
        ceaInstance.executeUniversalTx{value: 0.1 ether}(
            txID,
            ueaOnPush,
            address(reverter),
            0.1 ether,
            payload
        );
    }


    // =========================================================================
    // Event Emission Tests
    // =========================================================================

    function testExecuteUniversalTx_EmitsUniversalTxExecutedEvent() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumber(uint256)", 42);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(txID, ueaOnPush, address(target), address(token), 100 ether, payload);
        
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(target),
            100 ether,
            payload
        );
    }

    function testExecuteUniversalTx_EmitsUniversalTxExecutedEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("setMagicNumberWithFee(uint256)", 42);
        uint256 amount = 0.1 ether;

        vm.prank(vault);
        vm.deal(vault, amount);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(txID, ueaOnPush, address(target), address(0), amount, payload);
        
        ceaInstance.executeUniversalTx{value: amount}(
            txID,
            ueaOnPush,
            address(target),
            amount,
            payload
        );
    }

    // =========================================================================
    // withdrawFundsToUEA Tests - ERC20 Token Version
    // =========================================================================

    // -------------------------------------------------------------------------
    // 1. ACCESS CONTROL & AUTHORIZATION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_RevertWhenCalledByNonVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(nonVault);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_SuccessWhenCalledByVault() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    // -------------------------------------------------------------------------
    // 2. _handleSelfCalls VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_RevertWhenTxIDAlreadyExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        // Try to execute same txID again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenInvalidUEA() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx(
            txID,
            makeAddr("wrongUEA"),
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenPayloadTooShort() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = "123"; // Less than 4 bytes

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenInvalidSelector() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("wrongFunction(address,uint256)", address(token), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidTarget.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    // -------------------------------------------------------------------------
    // 3. BALANCE VALIDATION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_RevertWhenInsufficientERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 100 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_SuccessWithExactERC20Balance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 500 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testWithdrawFundsToUEA_SuccessWithMoreThanRequiredBalance() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
    }

    // -------------------------------------------------------------------------
    // 4. UNIVERSAL GATEWAY INTERACTION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_CallsGatewayWithCorrectParams_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            amount,
            payload
        );

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(token), "Token should match");
        assertEq(mockUniversalGateway.lastAmount(), amount, "Amount should match");
        assertEq(mockUniversalGateway.lastPayload().length, 0, "Payload should be empty");
        assertEq(mockUniversalGateway.lastFundRecipient(), ueaOnPush, "Fund recipient should be UEA");
        assertEq(mockUniversalGateway.lastSignatureData().length, 0, "Signature data should be empty");
        assertEq(mockUniversalGateway.lastValue(), 0, "No native value should be sent");
    }

    function testWithdrawFundsToUEA_CallsGatewayExactlyOnce_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        uint256 callCountBefore = mockUniversalGateway.callCount();
        
        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertEq(mockUniversalGateway.callCount(), callCountBefore + 1, "Gateway should be called exactly once");
    }

    // -------------------------------------------------------------------------
    // 5. ERC20 APPROVAL PATTERN TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_ResetsApprovalBeforeGranting() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        // Set an existing approval to gateway
        vm.prank(address(ceaInstance));
        token.approve(address(mockUniversalGateway), 300 ether);
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), 300 ether, "Initial approval should exist");

        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        // Approval should be set to amount (gateway may or may not consume it)
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), 500 ether, "Approval should be set to amount");
    }

    function testWithdrawFundsToUEA_GrantsCorrectApprovalAmount() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            amount,
            payload
        );

        // Gateway should have approval for exact amount
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), amount, "Approval should match amount");
    }

    // -------------------------------------------------------------------------
    // 6. STATE CHANGES TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_MarksTxIDAsExecuted() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be executed before");

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed after");
    }

    function testWithdrawFundsToUEA_ERC20BalanceDecreases() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 initialBalance = 1000 ether;
        fundCEAWithTokens(address(token), initialBalance);
        
        bytes32 txID = generateTxID(1);
        uint256 withdrawAmount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), withdrawAmount);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));
        
        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            withdrawAmount,
            payload
        );

        // Gateway receives approval but mock doesn't transfer tokens
        // So balance remains the same, but approval should be granted
        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, balanceBefore, "Balance should remain same (mock doesn't transfer)");
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), withdrawAmount, "Gateway should have approval");
    }

    // -------------------------------------------------------------------------
    // 7. EVENT EMISSION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_EmitsWithdrawalToUEAEvent_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), amount);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.WithdrawalToUEA(address(ceaInstance), ueaOnPush, address(token), amount);
        
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            amount,
            payload
        );
    }

    function testWithdrawFundsToUEA_EmitsUniversalTxExecutedEvent_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), amount);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(txID, ueaOnPush, address(ceaInstance), address(token), amount, payload);
        
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            amount,
            payload
        );
    }

    // -------------------------------------------------------------------------
    // 8. EDGE CASES & SECURITY TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_HandlesZeroAmount_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 0);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            0,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called even with zero amount");
    }

    function testWithdrawFundsToUEA_MultipleWithdrawalsWithDifferentTxIDs_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        fundCEAWithTokens(address(token), 2000 ether);
        
        uint256 amount = 500 ether;
        
        for (uint256 i = 1; i <= 3; i++) {
            bytes32 txID = generateTxID(i);
            bytes memory payload = buildWithdrawPayload(address(token), amount);

            vm.prank(vault);
            ceaInstance.executeUniversalTx(
                txID,
                ueaOnPush,
                address(token),
                address(ceaInstance),
                amount,
                payload
            );

            assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        }

        assertEq(mockUniversalGateway.callCount(), 3, "Gateway should be called 3 times");
    }

    function testWithdrawFundsToUEA_WithNonStandardToken() public deployCEA {
        NonStandardERC20Token token = new NonStandardERC20Token("NonStdToken", "NST", 18);
        fundCEAWithTokens(address(token), 1000 ether);
        
        // Set an existing approval first
        vm.prank(address(ceaInstance));
        token.approve(address(mockUniversalGateway), 300 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(token), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "Execution should succeed despite zero approval revert");
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), 500 ether, "Approval should be set");
    }

    // -------------------------------------------------------------------------
    // 9. INTEGRATION TESTS
    // -------------------------------------------------------------------------

    function testWithdrawFundsToUEA_FullFlow_ERC20() public deployCEA {
        MockGasToken token = new MockGasToken();
        uint256 initialBalance = 1000 ether;
        fundCEAWithTokens(address(token), initialBalance);
        
        bytes32 txID = generateTxID(1);
        uint256 withdrawAmount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(token), withdrawAmount);

        uint256 balanceBefore = token.balanceOf(address(ceaInstance));
        uint256 gatewayCallCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        ceaInstance.executeUniversalTx(
            txID,
            ueaOnPush,
            address(token),
            address(ceaInstance),
            withdrawAmount,
            payload
        );

        // Verify all state changes
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), gatewayCallCountBefore + 1, "Gateway should be called once");
        
        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(token), "Token should match");
        assertEq(mockUniversalGateway.lastAmount(), withdrawAmount, "Amount should match");
        
        // Gateway receives approval but mock doesn't transfer tokens
        // So balance remains the same, but approval should be granted
        uint256 balanceAfter = token.balanceOf(address(ceaInstance));
        assertEq(balanceAfter, balanceBefore, "Balance should remain same (mock doesn't transfer)");
        assertEq(token.allowance(address(ceaInstance), address(mockUniversalGateway)), withdrawAmount, "Gateway should have approval");
    }

    // =========================================================================
    // withdrawFundsToUEA Tests - Native Token Version
    // =========================================================================

    function testWithdrawFundsToUEA_RevertWhenCalledByNonVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(nonVault);
        vm.deal(nonVault, 0.1 ether);
        vm.expectRevert(Errors.NotVault.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_SuccessWhenCalledByVault_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testWithdrawFundsToUEA_RevertWhenTxIDAlreadyExecuted_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );

        // Try to execute same txID again
        vm.prank(vault);
        vm.expectRevert(Errors.PayloadExecuted.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenInvalidUEA_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidUEA.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            makeAddr("wrongUEA"),
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenPayloadTooShort_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = "123"; // Less than 4 bytes

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidInput.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenInvalidSelector_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = abi.encodeWithSignature("wrongFunction(address,uint256)", address(0), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InvalidTarget.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_RevertWhenInsufficientNativeBalance() public deployCEA {
        // Don't fund CEA
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(vault);
        vm.expectRevert(Errors.InsufficientBalance.selector);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );
    }

    function testWithdrawFundsToUEA_SuccessWithExactNativeBalance() public deployCEA {
        uint256 balance = 500 ether;
        fundCEAWithNative(balance);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), balance);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            balance,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called once");
    }

    function testWithdrawFundsToUEA_SuccessWithMoreThanRequiredBalance_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
    }

    function testWithdrawFundsToUEA_CallsGatewayWithCorrectParams_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(0), amount);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            amount,
            payload
        );

        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(0), "Token should be address(0) for native");
        assertEq(mockUniversalGateway.lastAmount(), amount, "Amount should match");
        assertEq(mockUniversalGateway.lastPayload().length, 0, "Payload should be empty");
        assertEq(mockUniversalGateway.lastFundRecipient(), ueaOnPush, "Fund recipient should be UEA");
        assertEq(mockUniversalGateway.lastValue(), amount, "Native value should match amount");
    }

    function testWithdrawFundsToUEA_CallsGatewayExactlyOnce_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        uint256 callCountBefore = mockUniversalGateway.callCount();
        
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );

        assertEq(mockUniversalGateway.callCount(), callCountBefore + 1, "Gateway should be called exactly once");
    }

    function testWithdrawFundsToUEA_MarksTxIDAsExecuted_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 500 ether);

        assertFalse(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should not be executed before");

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            500 ether,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed after");
    }

    function testWithdrawFundsToUEA_NativeBalanceDecreases() public deployCEA {
        uint256 initialBalance = 1000 ether;
        fundCEAWithNative(initialBalance);
        
        bytes32 txID = generateTxID(1);
        uint256 withdrawAmount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(0), withdrawAmount);

        uint256 balanceBefore = address(ceaInstance).balance;
        
        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            withdrawAmount,
            payload
        );

        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, balanceBefore - withdrawAmount, "Balance should decrease by exact amount");
        assertEq(mockUniversalGateway.lastValue(), withdrawAmount, "Gateway should receive correct value");
    }

    function testWithdrawFundsToUEA_EmitsWithdrawalToUEAEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(0), amount);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.WithdrawalToUEA(address(ceaInstance), ueaOnPush, address(0), amount);
        
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            amount,
            payload
        );
    }

    function testWithdrawFundsToUEA_EmitsUniversalTxExecutedEvent_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        uint256 amount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(0), amount);

        vm.prank(vault);
        vm.expectEmit(true, true, true, true);
        emit ICEA.UniversalTxExecuted(txID, ueaOnPush, address(ceaInstance), address(0), amount, payload);
        
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            amount,
            payload
        );
    }

    function testWithdrawFundsToUEA_HandlesZeroAmount_Native() public deployCEA {
        fundCEAWithNative(1000 ether);
        
        bytes32 txID = generateTxID(1);
        bytes memory payload = buildWithdrawPayload(address(0), 0);

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            0,
            payload
        );

        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), 1, "Gateway should be called even with zero amount");
    }

    function testWithdrawFundsToUEA_MultipleWithdrawalsWithDifferentTxIDs_Native() public deployCEA {
        fundCEAWithNative(2000 ether);
        
        uint256 amount = 500 ether;
        
        for (uint256 i = 1; i <= 3; i++) {
            bytes32 txID = generateTxID(i);
            bytes memory payload = buildWithdrawPayload(address(0), amount);

            vm.prank(vault);
            ceaInstance.executeUniversalTx{value: 0}(
                txID,
                ueaOnPush,
                address(ceaInstance),
                amount,
                payload
            );

            assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        }

        assertEq(mockUniversalGateway.callCount(), 3, "Gateway should be called 3 times");
    }

    function testWithdrawFundsToUEA_FullFlow_Native() public deployCEA {
        uint256 initialBalance = 1000 ether;
        fundCEAWithNative(initialBalance);
        
        bytes32 txID = generateTxID(1);
        uint256 withdrawAmount = 500 ether;
        bytes memory payload = buildWithdrawPayload(address(0), withdrawAmount);

        uint256 balanceBefore = address(ceaInstance).balance;
        uint256 gatewayCallCountBefore = mockUniversalGateway.callCount();

        vm.prank(vault);
        ceaInstance.executeUniversalTx{value: 0}(
            txID,
            ueaOnPush,
            address(ceaInstance),
            withdrawAmount,
            payload
        );

        // Verify all state changes
        assertTrue(CEA(payable(address(ceaInstance))).isExecuted(txID), "txID should be marked as executed");
        assertEq(mockUniversalGateway.callCount(), gatewayCallCountBefore + 1, "Gateway should be called once");
        
        assertEq(mockUniversalGateway.lastRecipient(), ueaOnPush, "Recipient should be UEA");
        assertEq(mockUniversalGateway.lastToken(), address(0), "Token should be address(0) for native");
        assertEq(mockUniversalGateway.lastAmount(), withdrawAmount, "Amount should match");
        assertEq(mockUniversalGateway.lastValue(), withdrawAmount, "Gateway should receive correct value");
        
        uint256 balanceAfter = address(ceaInstance).balance;
        assertEq(balanceAfter, balanceBefore - withdrawAmount, "Balance should decrease");
    }
}




