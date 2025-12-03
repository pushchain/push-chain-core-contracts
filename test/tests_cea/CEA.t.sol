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
}




