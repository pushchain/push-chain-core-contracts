// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {BaseERC8183Hook} from "./BaseERC8183Hook.sol";
import {IAgenticCommerce} from "../interfaces/IAgenticCommerce.sol";
import {IAGWFactory} from "../interfaces/external/IAGWFactory.sol";
import {ISmartSession} from "../interfaces/external/ISmartSession.sol";
import {IUniversalEvaluator} from "../interfaces/IUniversalEvaluator.sol";
import {JobSpec, Mutability} from "../evaluator/Types.sol";   // enum Mutability { NONE, BOTH, CLIENT_ONLY, PROVIDER_ONLY }
import {RulesBindingHookErrors, ERC8183HookErrors, UniversalHookErrors} from "../libraries/Errors.sol";

/// @title UniversalHook
/// @notice The one hook for evaluated jobs: binds the job to the funding AGW's rules set, controls who may
///         replace the job's spec, and hands the spec to the UniversalEvaluator.
/// @dev - Rules binding (as RulesBindingHook): `beforeAction(fund)`; any revert leaves the job Open, nothing escrowed.
///      - Spec: the provider may replace it in `setBudget`, the client in `fund`, as the `mutability` flag in the
///        createJob description allows. Frozen in `afterAction(fund)`.
///      - Stateless for evaluation: the evaluator holds the spec, prepaid PC, snapshot answers and rounds.
///      - Storage continues the base at slot 50. Slots 50–53 match RulesBindingHook, so its proxy can be upgraded to this.
contract UniversalHook is BaseERC8183Hook {
    /// @notice The job ↔ rules set record.
    struct Binding {
        address agw;
        bytes32 rulesId;
    }

    // ───────── events ─────────

    /// @notice A job was bound to an AGW's rules set at `fund`.
    event RulesBound(uint256 indexed jobId, address indexed agw, bytes32 indexed rulesId);
    /// @notice The spec was replaced (by the provider in setBudget, or the client in fund).
    event SpecReplaced(uint256 indexed jobId, bool byProvider, bytes32 specHash);
    /// @notice The spec was frozen at `fund` and handed to the evaluator.
    event SpecFrozen(uint256 indexed jobId, bytes32 specHash);

    // ───────── storage — slots 50..103 (base owns 0..49) ─────────

    /// @notice AGW factory, used to prove the client is an AGW.
    address public AGW_FACTORY;                                  // slot 50
    /// @notice SmartSession engine, used to prove the rules set is live.
    address public SESSION_ENGINE;                               // slot 51
    /// @notice Job id → bound rules set.
    /// @dev - `rulesId` is not globally unique across wallets; always read with `agw`.
    mapping(uint256 => Binding) public rulesOf;               // slot 52
    /// @notice AGW → last job bound; live only while that job is Funded or Submitted.
    mapping(address => uint256) public liveJobOf;               // slot 53
    /// @notice The UniversalEvaluator. Jobs with a different evaluator only get the rules binding.
    address public EVALUATOR;                                   // slot 54
    uint256[49] private __gap;                                  // slots 55..103

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy.
    function initialize(address kernel_, address agwFactory_, address sessionEngine_, address evaluator_)
        external
        initializer
    {
        if (agwFactory_ == address(0) || sessionEngine_ == address(0) || evaluator_ == address(0)) revert ERC8183HookErrors.ZeroAddress();
        __BaseERC8183Hook_init(kernel_);
        AGW_FACTORY = agwFactory_;
        SESSION_ENGINE = sessionEngine_;
        EVALUATOR = evaluator_;
    }

    /// @notice Upgrade step for the RulesBindingHook proxy: sets the evaluator, which `initialize` can't (it already ran there).
    /// @dev - PREPARED FOR REVIEW: not in the original hook design; needed by its "upgrade the proxy in place" plan.
    ///      - Only the proxy's admin may call, so only through `ProxyAdmin.upgradeAndCall` in the upgrade transaction:
    ///        nobody can set the evaluator between the upgrade and this call.
    ///      - Migration only: refused once an evaluator is set (a fresh proxy sets it in `initialize`).
    ///      - Slots 50–53 (factory, engine, bindings, live jobs) are kept as they are.
    function initializeV2(address evaluator_) external reinitializer(2) {
        if (msg.sender != ERC1967Utils.getAdmin()) revert UniversalHookErrors.CallerIsNotProxyAdmin(msg.sender);
        if (EVALUATOR != address(0)) revert UniversalHookErrors.EvaluatorAlreadySet(EVALUATOR);
        if (evaluator_ == address(0)) revert ERC8183HookErrors.ZeroAddress();
        EVALUATOR = evaluator_;
    }

    /// @notice Whether an AGW currently holds a live job under this hook.
    /// @dev - Live = the recorded job is Funded or Submitted in the kernel.
    function isAGWBusy(address agw) public view returns (bool) {
        uint256 id = liveJobOf[agw];
        if (id == 0) return false;
        IAgenticCommerce.JobStatus s = IAgenticCommerce(KERNEL).getJob(id).status;
        return s == IAgenticCommerce.JobStatus.Funded || s == IAgenticCommerce.JobStatus.Submitted;
    }

    // ───────── setBudget: the provider may replace the spec ─────────

    /// @dev setBudget's optParams (provider): empty = keep the spec · otherwise = abi.encode(JobSpec), the replacement.
    function _postSetBudget(uint256 jobId, address, uint256, bytes memory newSpec) internal override {
        if (newSpec.length == 0) return;                                          // price only, spec unchanged
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        if (job.evaluator != EVALUATOR) return;                                   // not evaluated by us

        Mutability flag = _flag(bytes(job.description));
        if (flag != Mutability.BOTH && flag != Mutability.PROVIDER_ONLY) revert UniversalHookErrors.SpecChangeNotAllowed(flag);
        _requireSameFlag(newSpec, flag);

        IUniversalEvaluator(EVALUATOR).setSpec(jobId, newSpec);
        emit SpecReplaced(jobId, true, keccak256(newSpec));
    }

    // ───────── fund (before): rules binding ─────────

    /// @dev Checks, in order: optParams shape · client is an AGW · rules set live · AGW not busy.
    ///      - `caller` is the job's client — the kernel checks it before calling the hook.
    ///      - Runs in `beforeAction`, so any revert leaves the job Open with no escrow moved.
    function _preFund(uint256 jobId, address caller, bytes memory optParams) internal override {
        (bytes32 rulesId, , ) = _parseFundParams(optParams);
        if (!IAGWFactory(AGW_FACTORY).isWallet(caller)) revert RulesBindingHookErrors.CallerIsNotAGW(caller);
        if (!ISmartSession(SESSION_ENGINE).isPermissionEnabled(rulesId, caller)) {
            revert RulesBindingHookErrors.RulesNotLive(caller, rulesId);
        }
        if (isAGWBusy(caller)) revert RulesBindingHookErrors.AGWHasLiveJob(caller, liveJobOf[caller]); // 2nd read only on revert

        rulesOf[jobId] = Binding({agw: caller, rulesId: rulesId});
        liveJobOf[caller] = jobId;
        emit RulesBound(jobId, caller, rulesId);
    }

    // ───────── fund (after): the client may replace the spec; freeze it; start the snapshot ─────────

    /// @dev - The final spec: the client's replacement if sent, else the provider's (stored in the evaluator), else the description.
    ///      - It must hash to `expectedSpecHash`, so nobody can swap it between the client's look and its fund.
    ///      - `startSnapshot` stores it, freezes it and fires the "before" reads; if it reverts, so does fund.
    function _postFund(uint256 jobId, address, bytes memory optParams) internal override {
        IAgenticCommerce.Job memory job = IAgenticCommerce(KERNEL).getJob(jobId);
        if (job.evaluator != EVALUATOR) return;                                   // not evaluated by us: rules binding only

        (, bytes32 expectedSpecHash, bytes memory newSpec) = _parseFundParams(optParams);
        Mutability flag = _flag(bytes(job.description));

        bytes memory spec;
        if (newSpec.length > 0) {                                                 // the client replaces it
            if (flag != Mutability.BOTH && flag != Mutability.CLIENT_ONLY) revert UniversalHookErrors.SpecChangeNotAllowed(flag);
            _requireSameFlag(newSpec, flag);
            spec = newSpec;
            emit SpecReplaced(jobId, false, keccak256(newSpec));
        } else {                                                                  // keep the current one
            spec = IUniversalEvaluator(EVALUATOR).currentSpec(jobId);             //   the provider's replacement, if any
            if (spec.length == 0) spec = bytes(job.description);                  //   else the createJob description
        }

        bytes32 actual = keccak256(spec);
        if (actual != expectedSpecHash) revert UniversalHookErrors.SpecHashMismatch(expectedSpecHash, actual);

        IUniversalEvaluator(EVALUATOR).startSnapshot(jobId, spec);
        emit SpecFrozen(jobId, actual);
    }

    // ───────── submit (after): fix the end blocks, send the reads ─────────

    /// @dev Not in try/catch: if the evaluator can't fix the end blocks (a stale or unmoved height, or too little
    ///      gas), `submit` reverts and the provider submits again later. A catch here would let a provider send
    ///      just enough gas for the evaluator call to fail, then pick its own end blocks with `sendReads`.
    ///      Sending the reads stays best effort: the evaluator catches that part itself, after fixing the blocks.
    ///      `virtual` as every handler in BaseERC8183Hook is; the tests replay the earlier try/catch with it.
    function _postSubmit(uint256 jobId, address, bytes32, bytes memory) internal virtual override {
        if (IAgenticCommerce(KERNEL).getJob(jobId).evaluator != EVALUATOR) return;
        IUniversalEvaluator(EVALUATOR).verifyFromSubmit(jobId);
    }

    // ───────── helpers ─────────

    /// @dev fund's optParams:
    ///      - 32 bytes: just the rulesId (RulesBindingHook's format). Only for jobs not evaluated by us:
    ///        for ours, the zero expectedSpecHash can never match, so fund reverts.
    ///      - otherwise: abi.encode(bytes32 rulesId, bytes32 expectedSpecHash, bytes newSpec); empty newSpec = keep the spec.
    function _parseFundParams(bytes memory p)
        internal
        pure
        returns (bytes32 rulesId, bytes32 expectedSpecHash, bytes memory newSpec)
    {
        if (p.length == 32) return (abi.decode(p, (bytes32)), bytes32(0), "");
        if (p.length < 128) revert RulesBindingHookErrors.InvalidOptParams(p.length);                   // smallest valid encoding: 4 words
        return abi.decode(p, (bytes32, bytes32, bytes));
    }

    /// @dev The governing flag: always the one in the createJob description.
    function _flag(bytes memory description) internal pure returns (Mutability) {
        return abi.decode(description, (JobSpec)).mutability;
    }

    /// @dev A replacement must keep the same flag, so neither side can lock the other out by switching it.
    function _requireSameFlag(bytes memory newSpec, Mutability flag) internal pure {
        Mutability got = abi.decode(newSpec, (JobSpec)).mutability;              // not a JobSpec → reverts
        if (got != flag) revert UniversalHookErrors.FlagChanged(flag, got);
    }
}


