// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {UniversalCallback} from "../../src/UniversalCallback.sol";
import {ReadSpec, PendingRead, MIN_CONFIRMATIONS_FLOOR, MAX_CALLBACK_GAS_LIMIT} from "../../src/libraries/ReadTypes.sol";
import {UniversalCallbackErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";
import {IUniversalCallback} from "../../src/interfaces/IUniversalCallback.sol";
import {MockUniversalCore} from "../mocks/MockUniversalCore.sol";
import {MockVaultPC} from "../mocks/MockVaultPC.sol";

contract UniversalCallbackTest is Test {
    UniversalCallback callback;
    MockUniversalCore mockCore;
    MockVaultPC mockVault;

    address defaultAdmin = address(0xAAAA);
    address ueModule = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    address uvAdmin = address(0xBBBB);
    address user = address(0xCCCC);
    address pauser = address(0xDDDD);
    address vaultPC = makeAddr("vaultPC");

    ReadSpec defaultSpec;
    bytes4 constant CALLBACK_SEL = bytes4(keccak256("onResponse(uint256,bytes)"));

    function setUp() public {
        mockCore = new MockUniversalCore();
        mockVault = new MockVaultPC();

        UniversalCallback impl = new UniversalCallback();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore),
                address(mockVault),
                defaultAdmin
            )
        );
        callback = UniversalCallback(payable(address(proxy)));

        vm.startPrank(defaultAdmin);
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), uvAdmin);
        callback.grantRole(callback.PAUSER_ROLE(), pauser);
        callback.grantRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin);
        vm.stopPrank();

        defaultSpec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(user)
            }),
            query: abi.encode("someData"),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 10 ether
        });

        mockCore.setReadBaseFee("eip155", "1", 0.01 ether);
        mockCore.setChainHeight("eip155", 1000);
    }

    function test_Initialize_SetsState() public {
        assertEq(address(callback.universalCore()), address(mockCore));
        assertEq(callback.vaultPC(), address(mockVault));
        assertTrue(callback.hasRole(callback.DEFAULT_ADMIN_ROLE(), defaultAdmin));
        assertTrue(callback.hasRole(callback.UVCALLBACK_ADMIN_ROLE(), defaultAdmin));
        assertTrue(callback.hasRole(callback.UVCALLBACK_ADMIN_ROLE(), uvAdmin));
    }

    function test_Initialize_RevertWhen_ZeroAddressCore() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.ZeroAddressInit.selector));
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(0), address(mockVault), defaultAdmin
            )
        );
    }

    function test_Initialize_RevertWhen_ZeroAddressVault() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.ZeroAddressInit.selector));
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore), address(0), defaultAdmin
            )
        );
    }

    function test_Initialize_RevertWhen_ZeroAddressAdmin() public {
        UniversalCallback impl = new UniversalCallback();
        vm.expectRevert(); // AccessControl: admin cannot be zero
        new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                UniversalCallback.initialize.selector,
                address(mockCore), address(mockVault), address(0)
            )
        );
    }

    function test_RequestExternalRead_EmitsEvent() public {
        vm.deal(user, 10 ether);
        vm.prank(user);

        vm.expectEmit(false, true, true, true);
        emit IUniversalCallback.ReadRequested(
            0, defaultSpec, user, user, 1 ether
        );

        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
        assertGt(requestId, 0);
    }

    function test_RequestExternalRead_StoresPending() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        PendingRead memory p = callback.getPendingRead(requestId);
        address target = p.callbackTarget;
        address funder = p.originalFunder;
        uint256 deposited = p.feesDeposited;
        assertEq(target, user);
        assertEq(funder, user);
        assertEq(deposited, 1 ether);
        assertEq(p.protocolFee, 0.01 ether);
        assertEq(p.expiryHeight, defaultSpec.expiryPushChainHeight);
    }

    function test_RequestExternalRead_RevertWhen_InsufficientFee() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.InsufficientFee.selector, 0.001 ether, 0.01 ether)
        );
        callback.requestExternalReadSelf{value: 0.001 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_FeeExceedsMaxFee() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.maxFee = 0.5 ether;

        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.ExcessiveFee.selector, 1 ether, 0.5 ether)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyOwner() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.owner = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyChainNamespace() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.chainNamespace = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyChainId() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.account.chainId = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidAccountId.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_EmptyQuery() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.query = "";

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.EmptyQuery.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_MinConfirmationsBelowFloor() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.minConfirmations = 0;

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidMinConfirmations.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ZeroBlockNumber() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.blockNumber = 0;

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidBlockNumber.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_BlockNumberAboveOracleHeight() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.blockNumber = 1001; // oracle height is 1000

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidBlockNumber.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ExpiryNotInFuture() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        ReadSpec memory spec = defaultSpec;
        spec.expiryPushChainHeight = uint64(block.number);

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidExpiryHeight.selector));
        callback.requestExternalReadSelf{value: 1 ether}(
            spec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_DomainBlocked() public {
        vm.prank(uvAdmin);
        callback.updateBlockedDomain("eip155", "1", true);

        vm.deal(user, 10 ether);
        vm.prank(user);

        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.DomainBlocked.selector, "eip155", "1")
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_RequestExternalRead_RevertWhen_ZeroCallbackGasLimit() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.CallbackGasLimitExceeded.selector, uint64(0), MAX_CALLBACK_GAS_LIMIT)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 0
        );
    }

    function test_RequestExternalRead_RevertWhen_CallbackGasLimitExceedsMax() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.CallbackGasLimitExceeded.selector, MAX_CALLBACK_GAS_LIMIT + 1, MAX_CALLBACK_GAS_LIMIT)
        );
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, MAX_CALLBACK_GAS_LIMIT + 1
        );
    }

    function test_FulfillExternalCallback_Success() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        bytes memory resultData = abi.encode("result");

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.ReadFulfilled(requestId, resultData, 500, bytes32(uint256(0x123)));

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, resultData, 500, bytes32(uint256(0x123)));

        assertTrue(callback.isFulfilled(requestId));
    }

    function test_FulfillExternalCallback_RevertWhen_NotUEModule() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotUEModule.selector));
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));
    }

    function test_FulfillExternalCallback_RevertWhen_AlreadyFulfilled() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));

        vm.prank(ueModule);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalCallbackErrors.RequestAlreadyFulfilled.selector, requestId)
        );
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));
    }

    function test_FulfillExternalCallback_RevertWhen_InvalidRequestId() public {
        vm.prank(ueModule);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.InvalidCallbackTarget.selector));
        callback.fulfillExternalCallback(999, "", 0, bytes32(0));
    }

    function test_FulfillExternalCallback_CallbackReverts_EmitsCallbackFailed() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.mockCallRevert(
            user,
            abi.encodeWithSelector(CALLBACK_SEL, requestId, ""),
            abi.encodeWithSignature("CustomError()")
        );

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.CallbackFailed(requestId, abi.encodeWithSignature("CustomError()"));

        vm.prank(ueModule);
        callback.fulfillExternalCallback(requestId, "", 0, bytes32(0));
    }

    function test_ExpireExternalRead_Success() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.roll(defaultSpec.expiryPushChainHeight);

        vm.expectEmit(true, true, true, true);
        emit IUniversalCallback.RequestExpired(requestId, user);

        vm.prank(ueModule);
        callback.expireExternalRead(requestId);

        assertTrue(callback.isFulfilled(requestId));
    }

    function test_ExpireExternalRead_RevertWhen_NotYetExpired() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        // block.number is still below expiryHeight
        vm.prank(ueModule);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.RequestNotYetExpired.selector));
        callback.expireExternalRead(requestId);
    }

    function test_ExpireExternalRead_RevertWhen_NotUEModule() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        uint256 requestId = callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );

        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotUEModule.selector));
        callback.expireExternalRead(requestId);
    }

    function test_EstimateFee_Works() public view {
        uint256 fee = callback.estimateFee("eip155", "1", 50000);
        assertGe(fee, 0.01 ether);
    }

    function test_UpdateBlockedDomain_SetsValue() public {
        vm.prank(uvAdmin);
        callback.updateBlockedDomain("solana", "mainnet", true);

        assertTrue(callback.isDomainBlocked("solana", "mainnet"));
    }

    function test_UpdateBlockedDomain_RevertWhen_NotAdmin() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.CallerIsNotAdmin.selector));
        callback.updateBlockedDomain("solana", "mainnet", true);
    }

    function test_Pause_RevertWhen_NotPauser() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(UniversalCallbackErrors.UnauthorizedCaller.selector));
        callback.pause();
    }

    function test_Pause_BlocksNewRequests() public {
        vm.prank(pauser);
        callback.pause();

        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert();
        callback.requestExternalReadSelf{value: 1 ether}(
            defaultSpec, CALLBACK_SEL, 50000
        );
    }

    function test_SweepFees_OnlyDefaultAdmin() public {
        vm.deal(address(callback), 1 ether);
        address recipient = makeAddr("recipient");

        vm.prank(uvAdmin);
        vm.expectRevert();
        callback.sweepFees(payable(recipient), 0.5 ether);

        vm.prank(defaultAdmin);
        callback.sweepFees(payable(recipient), 0.5 ether);
        assertEq(recipient.balance, 0.5 ether);
    }

    receive() external payable {}
}
