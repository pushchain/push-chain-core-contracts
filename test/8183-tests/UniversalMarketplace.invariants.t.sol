// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {MarketplaceFixtures} from "./UniversalMarketplace.t.sol";
import {MockAGW} from "./mocks/MockAGW.sol";
import {UniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalMarketplace} from "../../src/agentic-commerce-8183/UniversalMarketplace.sol";
import {JobSpec} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {AgentCard, JobInputs, StartJobParams} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @notice Drives startJob through honest and misbehaving wallets on a swap card (one param), and the card's
///         modification, cancels and time. Records what every started job must look like.
contract MarketplaceHandler is MarketplaceFixtures {
    uint256 public cardId;
    address[] public agws;
    uint256[] public jobs;
    mapping(uint256 => bytes32) public expectedOrigin;
    uint256 public userTokenStart;
    uint256 public userAssetStart;
    uint256 public userEthStart;

    /// @notice Outcome counters. `started` and `refused` are the liveness evidence (afterInvariant); the three
    ///         "unexpected" counters must stay zero. Counters rather than vm.expectRevert: with
    ///         fail_on_revert = false an unmet expectation inside a handler is a discarded call.
    uint256 public started;
    uint256 public refused;
    uint256 public honestRefused;
    uint256 public misbehaviourAccepted;
    uint256 public wrongRefusal;

    constructor() {
        setUp();
        cardId = _registerSwap();
        userTokenStart = token.balanceOf(user);
        userAssetStart = pUSDC.balanceOf(user);
        userEthStart = user.balance;
    }

    function agwCount() external view returns (uint256) {
        return agws.length;
    }

    function jobCount() external view returns (uint256) {
        return jobs.length;
    }

    function marketplace() external view returns (address) {
        return address(mkt);
    }

    function job(uint256 jobId) external view returns (IAgenticCommerce.Job memory) {
        return kernel.getJob(jobId);
    }

    function balances(address who) external view returns (uint256 tokenBal, uint256 assetBal, uint256 ethBal) {
        return (token.balanceOf(who), pUSDC.balanceOf(who), who.balance);
    }

    /// @param misbehave 0 honest · 1 wallet creates two jobs · 2 wallet creates the job from another address.
    ///        An honest start on a free wallet MUST succeed; a misbehaving one MUST fail with its named error.
    function start(uint256 principalSeed, uint256 executeSeed, uint256 paramSeed, uint8 misbehave) external {
        uint8 mode = misbehave % 3;
        (uint96 index, address agw, bool deployed) = _freeWallet();
        JobInputs memory j = _swapInputs(int256(bound(paramSeed, 1, 1e30)));
        j.principal = bound(principalSeed, 100e6, 1_000e6);
        j.executeBy = uint48(bound(executeSeed, block.timestamp + 10 minutes, j.expiredAt - 2 hours));
        StartJobParams memory p = _readyAt(cardId, index, _rules(), j);

        if (mode != 0 && !deployed) {
            vm.prank(user);
            factory.deployWalletWithSig(p.intent, "", "");
            deployed = true;
        }
        if (deployed) MockAGW(payable(agw)).setMode(MockAGW.Mode(mode));

        uint256 before = kernel.jobCounter();
        vm.prank(relayer);
        try mkt.startJob(p) returns (uint256 jobId, address, bytes32) {
            if (mode == 0) {
                started++;
                _record(agw, jobId, j.principal);
            } else {
                misbehaviourAccepted++;
            }
        } catch (bytes memory err) {
            if (mode == 0) {
                honestRefused++;
            } else {
                refused++;
                bytes memory expected = mode == 1
                    ? abi.encodeWithSelector(UniversalMarketplaceErrors.UnexpectedJobCount.selector, before, before + 2)
                    : abi.encodeWithSelector(UniversalMarketplaceErrors.JobMismatch.selector);
                if (keccak256(err) != keccak256(expected)) wrongRefusal++;
            }
        }
        if (deployed) MockAGW(payable(agw)).setMode(MockAGW.Mode.Honest);
    }

    /// @notice The provider re-publishes the card: same content, next version.
    function modify() external {
        AgentCard memory c = _card();
        c.jobType = keccak256("SWAP");
        bytes memory r = abi.encode(_rules());
        bytes memory e = abi.encode(_swapTemplate());
        vm.prank(provider);
        mkt.modifyAgentCard(cardId, c, r, e);
    }

    function cancel(uint256 seed) external {
        if (agws.length == 0) return;
        uint256 id = mkt.lastJobOf(agws[seed % agws.length]);
        if (id == 0 || kernel.getJob(id).status != IAgenticCommerce.JobStatus.Open) return;
        vm.prank(provider);
        kernel.reject(id, bytes32(0), "");
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 10 days));
    }

    /// @dev The user's last wallet if it is free, else the next one.
    function _freeWallet() internal view returns (uint96 index, address agw, bool deployed) {
        index = uint96(factory.walletCount(user));
        (agw, deployed) = factory.predictWallet(user, index);
        if (index == 0) return (index, agw, deployed);
        (address last,) = factory.predictWallet(user, index - 1);
        if (mkt.isAGWFree(last)) return (index - 1, last, true);
    }

    function _record(address agw, uint256 jobId, uint256 principal) internal {
        jobs.push(jobId);
        expectedOrigin[jobId] = keccak256(abi.encode(address(mkt), cardId, mkt.cardVersion(cardId), principal));
        for (uint256 i; i < agws.length; ++i) {
            if (agws[i] == agw) return;
        }
        agws.push(agw);
    }
}

/// @title UniversalMarketplace — invariants (PRD 09 §7.4).
/// @dev 64 runs × depth 100 per invariant (6,400 handler calls each): every call is a full startJob with criteria
///      built on-chain, so the defaults (256 × 500, five campaigns) take ~26 minutes.
/// forge-config: default.invariant.runs = 64
/// forge-config: default.invariant.depth = 100
contract UniversalMarketplaceInvariants is Test {
    MarketplaceHandler internal h;
    UniversalMarketplace internal mkt;
    address internal user = makeAddr("userUEA");

    function setUp() public {
        h = new MarketplaceHandler();
        mkt = UniversalMarketplace(h.marketplace());

        targetContract(address(h));
        bytes4[] memory sels = new bytes4[](4);
        sels[0] = MarketplaceHandler.start.selector;
        sels[1] = MarketplaceHandler.modify.selector;
        sels[2] = MarketplaceHandler.cancel.selector;
        sels[3] = MarketplaceHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sels}));
    }

    /// @notice A recorded job always belongs to the AGW it is recorded under.
    function invariant_MI01_lastJobOfIsTheAgwsOwnJob() public view {
        uint256 n = h.agwCount();
        for (uint256 i; i < n; ++i) {
            address agw = h.agws(i);
            uint256 id = mkt.lastJobOf(agw);
            if (id == 0) continue;
            assertEq(h.job(id).client, agw, "lastJobOf points at a job the AGW is not client of");
            assertEq(mkt.agwOfJob(id), agw);
        }
    }

    /// @notice The marketplace never holds the payment token, the rules asset or PC.
    function invariant_MI02_marketplaceHoldsNothing() public view {
        (uint256 tokenBal, uint256 assetBal, uint256 ethBal) = h.balances(address(mkt));
        assertEq(tokenBal, 0);
        assertEq(assetBal, 0);
        assertEq(ethBal, 0);
    }

    /// @notice An honest start on a free wallet always succeeds; a misbehaving wallet is always refused, with
    ///         its own named error.
    function invariant_MI03_outcomesExactlyExpected() public view {
        assertEq(h.honestRefused(), 0, "an honest startJob on a free wallet reverted");
        assertEq(h.misbehaviourAccepted(), 0, "a misbehaving wallet's startJob succeeded");
        assertEq(h.wrongRefusal(), 0, "a misbehaving wallet was refused with the wrong error");
    }

    /// @notice Every started job carries well-formed criteria with the recorded origin, the configured evaluator
    ///         and hook, and is never Funded (only the test funds, and this handler never does).
    function invariant_MI04_everyJobIsWellFormed() public view {
        uint256 n = h.jobCount();
        for (uint256 i; i < n; ++i) {
            uint256 id = h.jobs(i);
            IAgenticCommerce.Job memory j = h.job(id);
            JobSpec memory spec = abi.decode(bytes(j.description), (JobSpec));
            assertEq(spec.origin, h.expectedOrigin(id), "origin");
            assertEq(j.evaluator, mkt.evaluator(), "evaluator");
            assertEq(j.hook, mkt.hook(), "hook");
            assertTrue(j.status != IAgenticCommerce.JobStatus.Funded, "funded by nobody");
        }
    }

    /// @notice startJob never moves the user's tokens or PC.
    function invariant_MI05_userBalanceNeverMovedByStartJob() public view {
        (uint256 tokenBal, uint256 assetBal, uint256 ethBal) = h.balances(user);
        assertEq(tokenBal, h.userTokenStart());
        assertEq(assetBal, h.userAssetStart());
        assertEq(ethBal, h.userEthStart());
    }

    /// @notice Liveness: the run reached BOTH paths, or every invariant above held vacuously.
    function afterInvariant() public view {
        assertGt(h.started(), 0, "no honest startJob ever succeeded");
        assertGt(h.refused(), 0, "no misbehaving startJob was ever refused");
    }
}
