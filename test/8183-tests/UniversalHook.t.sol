// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {JobSpec, Mutability} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {EvmQueryEnvelope} from "../../src/agentic-commerce-8183/evaluator/ReadRequest.sol";
import {
    RulesBindingHookErrors,
    UniversalHookErrors,
    UniversalEvaluatorErrors,
    JobSpecErrors,
    ReadRequestErrors
} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {ReadSpec, PendingRead, RequestStatus} from "../../src/libraries/ReadTypes.sol";

/// @notice The UniversalHook (rules binding, spec replacement and freezing) and the snapshot the evaluator takes
///         inside `fund`.
contract UniversalHookTest is UniversalEvalBase {
    // ───────────── binding (RulesBindingHook's rules, kept) ─────────────

    function test_UH01_fund_bindsRules_freezesSpec_recordsCheckpoint() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        (address boundAgw, bytes32 rulesId) = hook.rulesOf(jobId);
        assertEq(boundAgw, address(agw));
        assertEq(rulesId, RULES);
        assertEq(hook.liveJobOf(address(agw)), jobId);

        UniversalEvaluator.JobCache memory c = ue.cacheOf(jobId);
        assertTrue(c.frozen && c.specIsDescription && c.checkpointOk);
        assertEq(c.specHash, keccak256(bytes(kernel.getJob(jobId).description)));
        assertEq(c.checkpointAtFund, agw.checkpointCount(), "includes the funding call's own tick");
    }

    function test_UH02_fund_refusals() public {
        uint256 jobId = _createSpec(_swapSpec());
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(RulesBindingHookErrors.InvalidOptParams.selector, 64));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, abi.encode(RULES, RULES))));

        // the old 32-byte format carries no spec hash, so an evaluated job can't be funded with it
        bytes32 actual = keccak256(bytes(kernel.getJob(jobId).description));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.SpecHashMismatch.selector, bytes32(0), actual));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, abi.encode(RULES))));

        engine.setPermission(RULES, address(agw), false);
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(RulesBindingHookErrors.RulesNotLive.selector, address(agw), RULES));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
        engine.setPermission(RULES, address(agw), true);

        factory.setWallet(address(agw), false);
        fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(RulesBindingHookErrors.CallerIsNotAGW.selector, address(agw)));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    function test_UH03_oneLiveJobPerWallet() public {
        uint256 first = _createSpec(_anySpec());
        _fund(first);
        uint256 second = _createSpec(_anySpec());
        bytes memory fp = _fundParams(second);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(RulesBindingHookErrors.AGWHasLiveJob.selector, address(agw), first));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (second, BUDGET, fp)));
    }

    /// @dev A job judged by another evaluator only gets the binding, and the old 32-byte optParams work for it.
    function test_UH04_otherEvaluator_bindingOnly() public {
        address otherEvaluator = makeAddr("otherEvaluator");
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, otherEvaluator, _expiry(), "plain text", address(hook)))
        );
        uint256 jobId = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        _fundWith(jobId, abi.encode(RULES));
        (address boundAgw,) = hook.rulesOf(jobId);
        assertEq(boundAgw, address(agw));
        assertFalse(ue.cacheOf(jobId).frozen);
    }

    // ───────────── spec replacement (mutability) ─────────────

    /// @dev PROVIDER_ONLY: the provider replaces the spec when pricing; the client funds against the replacement's
    ///      hash, and that is what gets frozen and judged.
    function test_UH05_providerReplacesSpec_inSetBudget() public {
        JobSpec memory s = _swapSpec();
        s.mutability = Mutability.PROVIDER_ONLY;
        uint256 jobId = _createSpec(s);

        JobSpec memory counter = _swapSpec();
        counter.mutability = Mutability.PROVIDER_ONLY;
        counter.checks[0].target = 0.37e18; // "I can do 0.37, not 0.38"
        bytes memory replacement = abi.encode(counter);
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, replacement);
        assertEq(ue.currentSpec(jobId), replacement);

        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        _fundWith(jobId, abi.encode(RULES, keccak256(replacement), bytes("")));
        UniversalEvaluator.JobCache memory c = ue.cacheOf(jobId);
        assertEq(c.specHash, keccak256(replacement));
        assertFalse(c.specIsDescription);

        _answerSnapshot(jobId, 0, 0);
        _advance();
        _submit(jobId);
        _answer(jobId, 0, abi.encode(uint256(0.375e18))); // passes 0.37, would fail 0.38
        assertEq(
            uint8(_status(jobId)),
            3 /* Completed */
        );
    }

    function test_UH06_replacementRefused_whenFlagForbids() public {
        uint256 jobId = _createSpec(_swapSpec()); // NONE
        JobSpec memory counter = _swapSpec();
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.SpecChangeNotAllowed.selector, Mutability.NONE));
        kernel.setBudget(jobId, BUDGET, abi.encode(counter));
    }

    function test_UH07_replacementMayNotChangeFlag() public {
        JobSpec memory s = _swapSpec();
        s.mutability = Mutability.BOTH;
        uint256 jobId = _createSpec(s);
        JobSpec memory counter = _swapSpec();
        counter.mutability = Mutability.CLIENT_ONLY;
        vm.prank(provider);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalHookErrors.FlagChanged.selector, Mutability.BOTH, Mutability.CLIENT_ONLY)
        );
        kernel.setBudget(jobId, BUDGET, abi.encode(counter));
    }

    /// @dev CLIENT_ONLY: the client sends its replacement with `fund`; the hash must be the replacement's.
    function test_UH08_clientReplacesSpec_inFund() public {
        JobSpec memory s = _anySpec();
        s.mutability = Mutability.CLIENT_ONLY;
        uint256 jobId = _createSpec(s);
        JobSpec memory mine = _anySpec();
        mine.mutability = Mutability.CLIENT_ONLY;
        mine.checks[0].target = 150e6;
        bytes memory replacement = abi.encode(mine);
        _prefund(jobId, 1 ether);

        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalHookErrors.SpecHashMismatch.selector, keccak256("wrong"), keccak256(replacement)
            )
        );
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.fund, (jobId, BUDGET, abi.encode(RULES, keccak256("wrong"), replacement)))
        );

        _fundWith(jobId, abi.encode(RULES, keccak256(replacement), replacement));
        assertEq(ue.cacheOf(jobId).specHash, keccak256(replacement));
    }

    function test_UH09_specFrozenAtFund() public {
        JobSpec memory s = _swapSpec();
        s.mutability = Mutability.PROVIDER_ONLY;
        uint256 jobId = _createSpec(s);
        _fund(jobId);
        vm.prank(address(hook));
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.SpecFrozen.selector, jobId));
        ue.setSpec(jobId, abi.encode(s));
    }

    // ───────────── criteria checks at fund ─────────────

    function test_UH10_undecodableDescription_refused() public {
        uint256 jobId = _createDescription("deposit 100 USDC into Aave");
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert();
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    function test_UH11_invalidSpec_refused() public {
        JobSpec memory s = _swapSpec();
        s.checks[0].read = 5;
        uint256 jobId = _createSpec(s);
        _prefund(jobId, 1 ether);
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.CheckRead.selector, 0));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    function test_UH12_untrackedChain_refused() public {
        JobSpec memory s = _anySpec();
        s.reads[1].chainId = "999999";
        uint256 jobId = _createSpec(s);
        _prefund(jobId, 1 ether);
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ReadRequestErrors.ChainNotTracked.selector, "eip155:999999"));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    /// @dev Trailing bytes after the encoded spec still decode; the length cap stops a bloated description.
    function test_UH13_specTooLong_refused() public {
        bytes memory desc = bytes.concat(abi.encode(_anySpec()), new bytes(33_000));
        uint256 jobId = _createDescription(string(desc));
        _prefund(jobId, 1 ether);
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(JobSpecErrors.SpecTooLong.selector, desc.length));
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    // ───────────── snapshot (inside fund) ─────────────

    /// @dev The node's envelope, at the tracked height, paid fee + 300k gas × base fee × 3, refunds to the client.
    function test_UH14_snapshotRequest_shapeHeightAndPayment() public {
        uint256 jobId = _createSpec(_swapSpec());
        vm.recordLogs();
        _fund(jobId);
        uint256 requestId = ue.snapshotRequestOf(jobId, 0);
        assertEq(ue.fundHeightOf(jobId, 0), START_HEIGHT);
        assertEq(ue.prepaidOf(jobId), READ_COST, "one round of after-reads left");

        PendingRead memory p = readState.getPendingRead(requestId);
        assertEq(p.callbackTarget, address(ue));
        assertEq(p.callbackGasLimit, 300_000);
        assertEq(p.callbackBudget, 300_000 * BASE_FEE * 3);
        assertEq(p.revertRecipient, address(agw));

        ReadSpec memory spec = _readSpecFromLogs(requestId);
        EvmQueryEnvelope memory env = abi.decode(spec.query, (EvmQueryEnvelope));
        assertEq(env.queryType, 1);
        assertEq(env.blockRef.refType, 0);
        assertEq(env.blockRef.blockNumber, START_HEIGHT);
        (address target, bytes memory callData) = abi.decode(env.payload, (address, bytes));
        assertEq(target, weth);
        assertEq(callData, abi.encodeWithSelector(bytes4(keccak256("balanceOf(address)")), cea));
        assertEq(spec.minConfirmations, 3);
    }

    function test_UH15_prepaidTooLow_fundReverts() public {
        uint256 jobId = _createSpec(_swapSpec());
        _prefund(jobId, SNAPSHOT_COST - 1);
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalEvaluatorErrors.PrepaidTooLow.selector, SNAPSHOT_COST, SNAPSHOT_COST - 1)
        );
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    function test_UH16_staleHeightAtFund_refused() public {
        uint256 jobId = _createSpec(_swapSpec());
        _prefund(jobId, 1 ether);
        vm.warp(block.timestamp + 2 hours); // tracked height last updated 2h ago, limit 1h
        bytes memory fp = _fundParams(jobId);
        vm.prank(owner);
        vm.expectRevert();
        agw.execute(address(kernel), 0, abi.encodeCall(kernel.fund, (jobId, BUDGET, fp)));
    }

    /// @dev An error answer leaves the snapshot read missing; a retry by the client or provider re-reads the SAME block.
    function test_UH17_snapshotRetry_sameBlock_clientOrProviderOnly() public {
        uint256 jobId = _createSpec(_swapSpec());
        _fund(jobId);
        uint256 first = ue.snapshotRequestOf(jobId, 0);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.NothingToRetry.selector, jobId));
        ue.retrySnapshot{value: SNAPSHOT_COST}(jobId); // still in flight

        assertTrue(_deliver(first, ""));
        assertFalse(ue.ready(jobId));

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.CallerIsNotClientOrProvider.selector, stranger));
        ue.retrySnapshot{value: SNAPSHOT_COST}(jobId);

        core.setChainHeight(BASE_KEY, START_HEIGHT + 500); // chain moved on; the retry must not follow it
        vm.recordLogs();
        vm.prank(provider);
        ue.retrySnapshot{value: SNAPSHOT_COST}(jobId);
        uint256 second = ue.snapshotRequestOf(jobId, 0);
        assertTrue(second != first);
        assertEq(_readSpecFromLogs(second).blockNumber, START_HEIGHT);

        assertTrue(_deliver(second, abi.encode(uint256(1e18))));
        assertTrue(ue.ready(jobId));
        (bool ok, int256 v) = ue.snapshotOf(jobId, 0);
        assertTrue(ok);
        assertEq(v, 1e18);
    }

    function test_UH18_prefundUnknownJob_refused() public {
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.UnknownJob.selector, 99));
        ue.prefund{value: 1}(99);
    }

    /// @dev On a freshly deployed hook the upgrade step can't replace the evaluator: not by a stranger, and not by the
    ///      proxy's admin through `upgradeAndCall` either.
    function test_UH19_initializeV2_migrationOnly() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotProxyAdmin.selector, stranger));
        hook.initializeV2(stranger);

        ProxyAdmin pa = ProxyAdmin(address(uint160(uint256(vm.load(address(hook), ERC1967Utils.ADMIN_SLOT)))));
        address impl = address(uint160(uint256(vm.load(address(hook), ERC1967Utils.IMPLEMENTATION_SLOT))));
        vm.prank(proxyAdminOwner);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.EvaluatorAlreadySet.selector, address(ue)));
        pa.upgradeAndCall(
            ITransparentUpgradeableProxy(address(hook)), impl, abi.encodeCall(UniversalHook.initializeV2, (stranger))
        );
        assertEq(hook.EVALUATOR(), address(ue));
    }

    /// @dev `NONE` is the zero value, so a spec whose encoder never sets `mutability` can't be replaced: not by the
    ///      provider in `setBudget`, not by the client in `fund`. In the hook design's order the zero value was
    ///      `BOTH`, which let both sides replace such a spec.
    function test_UH20_unsetMutability_isNone_refusesReplacement() public {
        assertEq(uint8(Mutability.NONE), 0, "NONE is the zero value");
        JobSpec memory s = _swapSpec();
        delete s.mutability; // as an encoder that never sets the field would leave it
        assertEq(uint8(s.mutability), uint8(Mutability.NONE));
        uint256 jobId = _createSpec(s);

        JobSpec memory r = _swapSpec();
        delete r.mutability;
        r.checks[0].target = 0.37e18;
        bytes memory replacement = abi.encode(r);

        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.SpecChangeNotAllowed.selector, Mutability.NONE));
        kernel.setBudget(jobId, BUDGET, replacement);

        bytes memory fp = abi.encode(RULES, keccak256(replacement), replacement);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.SpecChangeNotAllowed.selector, Mutability.NONE));
        _fundWith(jobId, fp);
    }
}
