// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AllowedMutability} from "./JobSpecTypes.sol";

/// @title UniversalMarketplaceErrors
/// @notice Every error the marketplace, its Terms helper and JobSpecBuilder raise.
/// @dev A library error has the same selector wherever it is raised, so a helper's revert bubbles through the
///      marketplace with the selector its callers expect.
library UniversalMarketplaceErrors {
    // ───────── config and cards ─────────

    error ZeroAddress();
    error HookNotWhitelisted();
    error CardInactive();
    /// @dev The caller is not the card's provider (or the card does not exist).
    error CallerIsNotProvider();
    error CardAdminDisabled(uint256 cardId);
    error ChainNotSupported(bytes32 chainHash);
    error ChainPaused(bytes32 chainHash);
    /// @dev The single registration error; every `reason` is listed in PRD 09 Appendix A.
    error InvalidCard(string reason);
    /// @dev `provided` is not the card's `current` version (startJob, verifyAgentCard).
    error CardVersionMismatch(uint256 provided, uint256 current);
    /// @dev `modifyAgentCard` tried to change the card's execution chain.
    error CardIdentityImmutable();

    // ───────── startJob: the job ─────────

    error PrincipalOutOfRange();
    error ExpiryOutOfRange();
    error ExecuteByOutOfRange();
    /// @dev The configured evaluator is the card's provider (the evaluator changed after registration).
    error ProviderIsEvaluator();
    error ParamCountMismatch(uint256 expected, uint256 actual);
    error ParamOutOfRange(uint256 index, int256 value);
    /// @dev A PRINCIPAL_BPS target overflows: `principal × bps` does not fit uint256.
    error TargetOverflow(uint256 check);
    /// @dev The card's template writes fill `fill` of read `read` outside that read's args.
    error FillOutOfBounds(uint256 read, uint256 fill);

    // ───────── startJob: wallet and intent (same shapes as the AGW's errors of the same name) ─────────

    error IntentWalletMismatch(address expected, address provided);
    error ExecutorMismatch(address expected, address actual);
    error IntentSessionMismatch(bytes32 actual);
    error IntentExecMismatch(bytes32 actualCalldataHash);
    error AGWBusy(address agw, uint256 jobId);
    error AGWMismatch(address expected, address actual);
    error WalletOwnerMismatch(address expected, address actual);

    // ───────── startJob: rules ⊆ card ─────────

    error AgentMismatch();
    error ActionCount();
    error PolicyShape(uint256 i);
    error ChainMismatch(uint256 i);
    error AssetMismatch();
    error PCCapMismatch();
    error ActionsMismatch();
    error CapMismatch();
    error ExpiryMismatch();
    error ExpectedCEAMismatch(address expected, address actual);

    // ───────── startJob: the created job ─────────

    error UnexpectedJobCount(uint256 before, uint256 afterCount);
    error JobMismatch();
}

/// @title ERC8183HookErrors
/// @notice The errors of BaseERC8183Hook, shared by every hook built on it.
library ERC8183HookErrors {
    /// @notice Caller is not the kernel.
    error CallerIsNotKernel(address caller);
    /// @notice A required address is zero.
    error ZeroAddress();
}

/// @title JobSpecErrors
/// @notice Why a job's criteria were refused at `fund`. Index arguments point into the `JobSpec` arrays.
library JobSpecErrors {
    /// @notice The encoded spec is longer than `MAX_DESCRIPTION_LENGTH`.
    error SpecTooLong(uint256 length);
    /// @notice `reads.length` is 0 or above `MAX_READS`.
    error ReadCount(uint256 count);
    /// @notice `checks.length` is 0 or above `MAX_CHECKS`.
    error CheckCount(uint256 count);
    /// @notice `logic.length` is 0 or above `MAX_LOGIC`.
    error LogicCount(uint256 count);
    /// @notice A read names an empty or too long chain namespace or chain id, or a namespace other than `eip155`.
    error ReadChain(uint256 read);
    /// @notice A read asks for zero confirmations, or more than the evaluator's maximum.
    error ReadConfirmations(uint256 read);
    /// @notice A read targets address zero.
    error ReadTarget(uint256 read);
    /// @notice A read's `args` are longer than `MAX_ARGS_LENGTH`.
    error ReadArgs(uint256 read);
    /// @notice A read's `outputs` / `field` do not name one value of a well-formed return type that fits
    ///         `MAX_RESULT_LENGTH`.
    error ReadShape(uint256 read);
    /// @notice A check side names a read that does not exist or is not in increasing order, or both sides name
    ///         the same read.
    error CheckRead(uint256 check);
    /// @notice A check's sides don't fit its type: BOOLEAN one `left` read and no `right` · COMPARE no `right` ·
    ///         NUMBER / PERCENTAGE both sides.
    error CheckSides(uint256 check);
    /// @notice No read is POST_EXECUTION, so the provider's work would never be measured.
    error NoPostExecutionRead();
    /// @notice A BOOLEAN check's target is neither 0 nor 1.
    error CheckTarget(uint256 check);
    /// @notice A BOOLEAN check's operator is not `EQUAL`.
    error CheckOp(uint256 check);
    /// @notice A logic entry is malformed: bad check index, children out of order or out of range, or a bad `k`.
    error LogicShape(uint256 entry);
    /// @notice A logic entry no path from the root reaches.
    error LogicUnreachable(uint256 entry);
    /// @notice A check no reachable logic entry uses.
    error CheckUnused(uint256 check);
    /// @notice A read no used check reads.
    error ReadUnused(uint256 read);
}

/// @title EvmReadErrors
/// @notice Why a Read State request could not be sent.
library EvmReadErrors {
    /// @notice Push tracks no height for this chain.
    error ChainNotTracked(string chainKey);
    /// @notice Push's tracked height for this chain was last updated longer ago than allowed.
    error HeightStale(string chainKey, uint256 observedAt);
}

/// @title UniversalHookErrors
/// @notice The UniversalHook's errors: binding the rules set at `fund`, and replacing and freezing the spec.
library UniversalHookErrors {
    /// @notice `setAgwContracts` was not called by the proxy's admin.
    error CallerIsNotProxyAdmin(address caller);
    /// @notice `fund.optParams` is neither 32 bytes (the rulesId alone) nor long enough to hold
    ///         `(rulesId, specHash, newSpec)`.
    error InvalidOptParams(uint256 length);
    /// @notice The funding client is not a factory-deployed AGW.
    error CallerIsNotAGW(address caller);
    /// @notice The rules set is not enabled on this AGW.
    error RulesNotLive(address agw, bytes32 rulesId);
    /// @notice The AGW already has a Funded or Submitted job under this hook.
    error WalletHasActiveJob(address agw, uint256 jobId);
    /// @notice The job's mutability flag does not let this party replace the spec.
    error SpecChangeNotAllowed(AllowedMutability flag);
    /// @notice A replacement spec tried to change the mutability flag.
    error FlagChanged(AllowedMutability expected, AllowedMutability got);
    /// @notice The spec being frozen is not the one the client agreed to.
    error SpecHashMismatch(bytes32 expected, bytes32 actual);
}

/// @title UniversalEvaluatorErrors
/// @notice The UniversalEvaluator's errors.
library UniversalEvaluatorErrors {
    /// @notice A required address or config value is zero.
    error ZeroValue();
    /// @notice No such job on the kernel.
    error UnknownJob(uint256 jobId);
    /// @notice The job does not name this evaluator and the UniversalHook.
    error NotOurJob(uint256 jobId);
    /// @notice The job is not in the status this call needs.
    error WrongStatus(uint256 jobId);
    /// @notice The job's spec is already frozen.
    error SpecFrozen(uint256 jobId);
    /// @notice The job's PC does not cover a read.
    error PrepaidTooLow(uint256 needed, uint256 available);
    /// @notice A PRE_EXECUTION read has no answer yet.
    error SnapshotNotReady(uint256 jobId);
    /// @notice No read to send: every one is answered or still in flight, or the job is decided.
    error NothingToSend(uint256 jobId);
    /// @notice No PASS or FAIL verdict waiting for the kernel.
    error NothingToSettle(uint256 jobId);
    /// @notice The job is still live, so its PC is still needed.
    error JobStillLive(uint256 jobId);
    /// @notice Caller is not the UniversalHook.
    error CallerIsNotHook(address caller);
    /// @notice Caller is not Read State.
    error CallerIsNotReadState(address caller);
    /// @notice Caller is not the job's provider.
    error CallerIsNotProvider(address caller);
    /// @notice Caller is neither the job's client nor its provider.
    error CallerIsNotClientOrProvider(address caller);
    /// @notice Only the evaluator itself may call this.
    error CallerIsNotSelf(address caller);
    /// @notice Sending PC to the job's client failed.
    error RefundFailed(address to, uint256 amount);
    /// @notice Read State has blocked this read's chain, so it could never be sent.
    error ReadDomainBlocked(uint256 read);
    /// @notice The read's tracked height has not moved past the one recorded at `fund`.
    error EndHeightNotAfterFund(uint256 jobId, uint256 read, uint64 fundHeight, uint64 endHeight);
    /// @notice The end blocks were not fixed at `submit`: the hook never called the evaluator, because the kernel
    ///         admin detached the job's hook before `submit` (`batchDetachHook`), or the hook had no evaluator set.
    error EndBlocksNotFixed(uint256 jobId);
}
