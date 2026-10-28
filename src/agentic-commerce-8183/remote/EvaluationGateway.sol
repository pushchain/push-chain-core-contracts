// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {IUniversalGateway, UniversalTxRequest} from "../../interfaces/IUniversalGateway.sol";
import {ICEAFactory} from "../../interfaces/ICEAFactory.sol";
import {UniversalPayload, VerificationType} from "../../libraries/Types.sol";
import {JobSpec, Read, ReadAt} from "../libraries/JobSpecTypes.sol";
import {JobSpecErrors} from "../libraries/Errors.sol";
import {JobSpecLib} from "../evaluator/JobSpecLib.sol";
import {MAX_RESULT_LENGTH, MAX_DESCRIPTION_LENGTH} from "../evaluator/EvaluationTypes.sol";
import {InboundSender} from "./InboundSender.sol";
import {
    PushFees,
    RemoteJob,
    RemoteKeys,
    LAYOUT_V,
    LAYOUT_R,
    JOB_FUNDED,
    JOB_SUBMITTED,
    VERDICT_NONE,
    VERDICT_PASS,
    VERDICT_FAIL,
    SNAPSHOT_SLOT,
    VERIFY_SLOT,
    IKernelLayoutV,
    IKernelLayoutR,
    IKernelVerdict,
    IUniversalGatewayVault,
    IVaultCEAFactory,
    IRemoteEvaluator,
    IEvaluationGateway,
    EvaluationGatewayErrors
} from "./RemoteTypes.sol";

/// @title EvaluationGateway — Push as the evaluator of a job on another chain
/// @notice A job on a supported ERC-8183 kernel names this contract as its `evaluator` and carries `abi.encode(JobSpec)`
///         as its description. Push judges it; this contract applies the verdict.
///         1. `snapshot` (the client, the job Funded): checks the job and its criteria and reads every PRE read on this
///            chain here, with `staticcall`. Read State would answer the same call with the same bytes (raw return
///            data, empty on revert), so Push decodes them with the Phase 1 decoder. When the criteria have PRE reads on
///            other chains, it also sends the snapshot inbound, so Push pins them now, before the work.
///         2. `verify` (the provider, the job Submitted): fixes E = this block, reads here every `POST_AT_VERIFY`
///            read (values only the client can move, which the provider can't change inside his own call), and sends
///            it all to the RemoteEvaluator on Push as the verify inbound. Push reads every other POST read through
///            Read State: on this chain at the end of block E, on another chain at its fresh tracked height. When
///            nothing is left for Read State, Push decides inside that inbound and the verdict comes straight back.
///         3. `settle` (the RemoteEvaluator's CEA only): records the verdict and tries `complete` / `reject`.
/// @dev - The provider can't measure inside its own transaction: POST values are end-of-block reads, so a change made
///        and undone inside one transaction (a flash loan, a half-updated protocol) is not what Push sees.
///      - PRE values are read inside the client's call, which the client could shape; the provider compares them with
///        an `eth_call` at the end of block S before working, and does not start if they differ.
///      - Hooks: only `address(0)` or `NOOP_HOOK`. A hook runs inside `complete` and could block payment, while
///        `claimRefund` runs no hook.
///      - Kernels and their `Job` layout are fixed in `initialize`; an unlisted address is never read as a kernel.
///      - Each inbound goes through its own InboundSender (CREATE2 for one job and slot), so Push runs it from its own
///        UEA with payload nonce 0. A UEA shared by every job would need its next nonce, which this chain can't know,
///        and a payload that fails on Push leaves the nonce unchanged. The RemoteEvaluator recognises a job's senders
///        by their CREATE2 address.
///      - Nothing here reverts a verdict: `settle` records it and tries the kernel inside a low-level call, so the
///        outbound never fails because of the kernel; `applyVerdict` retries later.
///      - Behind a TransparentUpgradeableProxy while testing, with settings written once in `initialize` and no
///        setter. The UniversalEvaluator is not upgradeable; before mainnet this contract becomes the same (or
///        timelocked): whoever can upgrade it can complete or reject every job on its chain.
contract EvaluationGateway is IEvaluationGateway, Initializable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice What the gateway keeps per job.
    struct Record {
        bytes32 specHash; // keccak256 of the description, at snapshot
        bytes32 preHash; // keccak256(abi.encode(preResults))
        uint64 snapshotBlock; // S
        uint64 verifyBlock; // E, zero until verify
        bytes32 verifyHash; // keccak256(abi.encode(verifyResults)): the values read inside `verify`
        uint8 verdict; // VERDICT_NONE / PASS / FAIL
        bool applied; // the kernel accepted the verdict
        bool snapshotInbound; // `snapshot` sent an inbound (PRE reads on other chains)
        bytes32 reason;
    }

    /// @notice Settings, as `initialize` takes them.
    struct Config {
        address universalGateway; // this chain's UniversalGateway
        address remoteEvaluator; // the RemoteEvaluator proxy on Push
        address noopHook; // the only non-zero hook accepted
        address feeRecipient; // evaluator fees paid by kernels, and stray native
        uint256 readGas; // gas each local read gets
        uint256 minSettleWindow; // least time before `expiredAt` to start `verify`
        uint16 maxConfirmations; // must equal the RemoteEvaluator's, so both sides validate alike
        address[] kernels;
        uint8[] layouts;
    }

    // ───────── events ─────────

    event Snapshotted(
        address indexed kernel, uint256 indexed jobId, bytes32 specHash, uint64 snapshotBlock, bytes[] preResults
    );
    event VerifySent(
        address indexed kernel, uint256 indexed jobId, bytes32 captureKey, uint64 verifyBlock, bytes[] verifyResults
    );
    event InboundSent(
        address indexed kernel,
        uint256 indexed jobId,
        uint32 slot,
        address sender,
        bytes4 call,
        uint256 gas,
        uint256 pcForJob
    );
    event VerdictRecorded(address indexed kernel, uint256 indexed jobId, bytes32 captureKey, bool pass, bytes32 reason);
    event VerdictApplied(address indexed kernel, uint256 indexed jobId, bool pass);
    event ApplyFailed(address indexed kernel, uint256 indexed jobId, bytes reason);
    event SettleIgnored(address indexed kernel, uint256 indexed jobId, bytes32 captureKey);
    event InvalidRejected(address indexed kernel, uint256 indexed jobId);
    event Swept(address indexed token, address indexed to, uint256 amount);

    /// @notice Gas kept back around a local read, for the call itself and copying its answer.
    uint256 internal constant READ_OVERHEAD = 10_000;

    // ───────── configuration, written once in `initialize` ─────────

    IUniversalGateway public UGW;
    address public REMOTE_EVALUATOR;
    address public NOOP_HOOK;
    address public FEE_RECIPIENT;
    uint256 public READ_GAS;
    uint256 public MIN_SETTLE_WINDOW;
    uint16 public MAX_CONFIRMATIONS;
    /// @notice A kernel's `Job` layout (`LAYOUT_V`, `LAYOUT_R`); 0 for an unsupported address.
    mapping(address => uint8) public layoutOf;

    // ───────── storage ─────────

    mapping(address => mapping(uint256 => Record)) internal _records;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(Config calldata c) external initializer {
        if (
            c.universalGateway == address(0) || c.remoteEvaluator == address(0) || c.noopHook == address(0)
                || c.feeRecipient == address(0) || c.readGas == 0 || c.minSettleWindow == 0 || c.maxConfirmations == 0
                || c.kernels.length == 0
        ) revert EvaluationGatewayErrors.ZeroValue();
        if (c.kernels.length != c.layouts.length) revert EvaluationGatewayErrors.LayoutsMismatch();
        UGW = IUniversalGateway(c.universalGateway);
        REMOTE_EVALUATOR = c.remoteEvaluator;
        NOOP_HOOK = c.noopHook;
        FEE_RECIPIENT = c.feeRecipient;
        READ_GAS = c.readGas;
        MIN_SETTLE_WINDOW = c.minSettleWindow;
        MAX_CONFIRMATIONS = c.maxConfirmations;
        for (uint256 i; i < c.kernels.length; ++i) {
            address k = c.kernels[i];
            uint8 l = c.layouts[i];
            if (k == address(0) || k.code.length == 0 || (l != LAYOUT_V && l != LAYOUT_R) || layoutOf[k] != 0) {
                revert EvaluationGatewayErrors.BadLayout(k, l);
            }
            layoutOf[k] = l;
        }
    }

    // ═════════════════════════════════ the job's parties ═════════════════════════════════

    /// @notice The client takes the PRE values, once, while the job is Funded: those on this chain here; those on
    ///         other chains through the snapshot inbound (paid with `msg.value`, priced with `fees`), which Push pins at
    ///         its tracked heights. Without PRE reads on other chains no inbound is sent and `msg.value` must be 0.
    function snapshot(address kernel, uint256 jobId, PushFees calldata fees) external payable nonReentrant {
        RemoteJob memory job = _job(kernel, jobId);
        if (job.evaluator != address(this)) revert EvaluationGatewayErrors.NotOurJob(kernel, jobId);
        if (job.status != JOB_FUNDED) revert EvaluationGatewayErrors.WrongStatus(kernel, jobId, job.status);
        if (msg.sender != job.client) revert EvaluationGatewayErrors.NotClient(msg.sender);
        Record storage r = _records[kernel][jobId];
        if (r.snapshotBlock != 0) revert EvaluationGatewayErrors.AlreadySnapshotted(kernel, jobId);

        JobSpec memory s = _checkJob(job);
        bytes[] memory results = new bytes[](s.reads.length);
        bytes32 here = keccak256(bytes(Strings.toString(block.chainid)));
        bool elsewhere;
        for (uint256 i; i < s.reads.length; ++i) {
            if (s.reads[i].at != ReadAt.PRE_EXECUTION) continue;
            if (keccak256(bytes(s.reads[i].chainId)) == here) results[i] = _readHere(s.reads[i]);
            else elsewhere = true;
        }
        r.specHash = keccak256(bytes(job.description));
        r.preHash = keccak256(abi.encode(results));
        r.snapshotBlock = uint64(block.number);
        emit Snapshotted(kernel, jobId, r.specHash, r.snapshotBlock, results);
        if (elsewhere) {
            r.snapshotInbound = true;
            _send(
                kernel,
                jobId,
                SNAPSHOT_SLOT,
                abi.encodeCall(
                    IRemoteEvaluator.onRemoteJob,
                    (kernel, jobId, msg.sender, bytes(job.description), results, r.snapshotBlock, 0, new bytes[](0))
                ),
                fees
            );
        } else if (msg.value != 0) {
            revert EvaluationGatewayErrors.NoInboundNeeded();
        }
    }

    /// @notice The provider declares the work done: E = this block. The `POST_AT_VERIFY` values are read here, inside
    ///         this call, and the job goes to Push with them.
    /// @dev The provider should call this only once Push's tracked heights cover his work on other chains: their POST
    ///      reads are pinned at Push's fresh tracked height when the verify inbound runs (or later, by `sendReads`).
    /// @param spec       The job's description bytes (from the kernel).
    /// @param preResults The answers in the `Snapshotted` event.
    function verify(address kernel, uint256 jobId, bytes calldata spec, bytes[] calldata preResults, PushFees calldata fees)
        external
        payable
        nonReentrant
    {
        RemoteJob memory job = _job(kernel, jobId);
        if (job.evaluator != address(this)) revert EvaluationGatewayErrors.NotOurJob(kernel, jobId);
        if (job.status != JOB_SUBMITTED) revert EvaluationGatewayErrors.WrongStatus(kernel, jobId, job.status);
        if (msg.sender != job.provider) revert EvaluationGatewayErrors.NotProvider(msg.sender);
        Record storage r = _records[kernel][jobId];
        if (r.snapshotBlock == 0) revert EvaluationGatewayErrors.NoSnapshot(kernel, jobId);
        if (r.verifyBlock != 0) revert EvaluationGatewayErrors.AlreadyVerified(kernel, jobId);
        if (block.number <= r.snapshotBlock) revert EvaluationGatewayErrors.SameBlockAsSnapshot();
        if (block.timestamp + MIN_SETTLE_WINDOW > job.expiredAt) {
            uint256 latestStart = job.expiredAt > MIN_SETTLE_WINDOW ? job.expiredAt - MIN_SETTLE_WINDOW : 0;
            revert EvaluationGatewayErrors.TooCloseToExpiry(job.expiredAt, latestStart);
        }
        _checkCapture(r, spec, preResults);
        JobSpec memory s = abi.decode(spec, (JobSpec));
        bytes[] memory results = new bytes[](s.reads.length);
        for (uint256 i; i < s.reads.length; ++i) {
            if (s.reads[i].at == ReadAt.POST_AT_VERIFY) results[i] = _readHere(s.reads[i]);
        }
        r.verifyBlock = uint64(block.number);
        r.verifyHash = keccak256(abi.encode(results));
        emit VerifySent(kernel, jobId, _captureKey(kernel, jobId, r), r.verifyBlock, results);
        _sendJob(kernel, jobId, VERIFY_SLOT, r.verifyBlock, spec, preResults, results, fees);
    }

    /// @notice Sends one of the job's inbounds again, through the same sender: the snapshot inbound (`SNAPSHOT_SLOT`,
    ///         the client, only for a job whose `snapshot` sent one) or the verify inbound (`VERIFY_SLOT`, the provider,
    ///         once he verified). For a payload that failed on Push (too little gas, a low `maxFeePerGas`, too little
    ///         PC, a stale height, a verify that arrived before its snapshot, or one before Push's height on another
    ///         chain moved past the snapshot's); a failed payload leaves its sender's UEA nonce at 0, so the copy runs.
    ///         A copy of a payload that already ran fails on Push.
    /// @dev Only the party whose call it repeats, as the UniversalEvaluator lets only them `fund` and `submit`: Push
    ///      fixes blocks when the message runs, so whoever sends it chooses when the job is measured.
    /// @param verifyResults The values `verify` read (its `VerifySent` event); empty for the snapshot inbound.
    function resend(
        address kernel,
        uint256 jobId,
        uint32 slot,
        bytes calldata spec,
        bytes[] calldata preResults,
        bytes[] calldata verifyResults,
        PushFees calldata fees
    ) external payable nonReentrant {
        Record storage r = _records[kernel][jobId];
        if (r.snapshotBlock == 0) revert EvaluationGatewayErrors.NoSnapshot(kernel, jobId);
        if (r.verdict != VERDICT_NONE) revert EvaluationGatewayErrors.VerdictAlreadyRecorded(kernel, jobId);
        _checkCapture(r, spec, preResults);
        RemoteJob memory job = _job(kernel, jobId);
        uint64 verifyBlock;
        if (slot == SNAPSHOT_SLOT) {
            if (msg.sender != job.client) revert EvaluationGatewayErrors.NotClient(msg.sender);
            if (!r.snapshotInbound) revert EvaluationGatewayErrors.NoInboundNeeded();
            if (verifyResults.length != 0) revert EvaluationGatewayErrors.VerifyResultsMismatch();
        } else if (slot == VERIFY_SLOT) {
            if (msg.sender != job.provider) revert EvaluationGatewayErrors.NotProvider(msg.sender);
            if (r.verifyBlock == 0) revert EvaluationGatewayErrors.NotVerified(kernel, jobId);
            if (keccak256(abi.encode(verifyResults)) != r.verifyHash) {
                revert EvaluationGatewayErrors.VerifyResultsMismatch();
            }
            verifyBlock = r.verifyBlock;
        } else {
            revert EvaluationGatewayErrors.BadSlot(slot);
        }
        _sendJob(kernel, jobId, slot, verifyBlock, spec, preResults, verifyResults, fees);
    }

    // ═════════════════════════════════ anyone ═════════════════════════════════

    /// @notice Applies a recorded verdict the kernel refused when it arrived (paused kernel, for instance).
    function applyVerdict(address kernel, uint256 jobId) external nonReentrant {
        Record storage r = _records[kernel][jobId];
        if (r.verdict == VERDICT_NONE || r.applied) revert EvaluationGatewayErrors.NothingToApply(kernel, jobId);
        (bool ok, bytes memory err) = _apply(kernel, jobId, r);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(err, 32), mload(err)) // the kernel's own revert
            }
        }
    }

    /// @notice Rejects a job that names this gateway but can never be judged here: criteria that fail validation or
    ///         read another chain, an over-long description, or a hook other than `address(0)` and `NOOP_HOOK`. The
    ///         client is refunded at once instead of at expiry.
    function rejectInvalid(address kernel, uint256 jobId) external nonReentrant {
        RemoteJob memory job = _job(kernel, jobId);
        if (job.evaluator != address(this)) revert EvaluationGatewayErrors.NotOurJob(kernel, jobId);
        if (job.status != JOB_FUNDED && job.status != JOB_SUBMITTED) {
            revert EvaluationGatewayErrors.WrongStatus(kernel, jobId, job.status);
        }
        bool hookOk = job.hook == address(0) || job.hook == NOOP_HOOK;
        if (hookOk) {
            uint256 g = gasleft();
            try this.checkSpec(bytes(job.description)) {
                revert EvaluationGatewayErrors.SpecIsValid(kernel, jobId);
            } catch {
                // A check that ran out of gas leaves under 1/64 of `g`: refuse it rather than reject a job whose
                // criteria may be valid. The caller retries with more gas.
                if (gasleft() < g / 63) revert EvaluationGatewayErrors.CheckRanOutOfGas();
            }
        }
        IKernelVerdict(kernel).reject(jobId, keccak256("EvaluationGateway: invalid job"), "");
        emit InvalidRejected(kernel, jobId);
    }

    /// @notice Sends this contract's balance of `token` (`address(0)`: native) to `FEE_RECIPIENT`. Kernels such as
    ///         Virtuals pay part of each completed budget to the job's evaluator.
    function sweep(address token) external nonReentrant {
        address to = FEE_RECIPIENT;
        uint256 amount;
        if (token == address(0)) {
            amount = address(this).balance;
            if (amount == 0) return;
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert EvaluationGatewayErrors.TransferFailed(to, amount);
        } else {
            amount = IERC20(token).balanceOf(address(this));
            if (amount == 0) return;
            IERC20(token).safeTransfer(to, amount);
        }
        emit Swept(token, to, amount);
    }

    // ═════════════════════════════════ the RemoteEvaluator's CEA ═════════════════════════════════

    /// @inheritdoc IEvaluationGateway
    /// @dev Never reverts once the caller is the RemoteEvaluator's CEA, so the outbound always completes:
    ///      - a verdict that doesn't match this job's record (a second copy, a replaced transaction) is ignored;
    ///      - a verdict on the snapshot alone (its capture key has no E) is taken only as a FAIL, before or after
    ///        `verify`: Push decides one when a read can never be answered, which it may first see in the verify
    ///        inbound, and a FAIL decided at the snapshot may land after the provider verified;
    ///      - the kernel call runs inside a low-level call; a refusal is kept for `applyVerdict`.
    function settle(address kernel, uint256 jobId, bytes32 captureKey, bool pass, bytes32 reason)
        external
        nonReentrant
    {
        _requireEvaluatorCEA();
        Record storage r = _records[kernel][jobId];
        bytes32 sk = _snapshotKey(kernel, jobId, r);
        bool onCapture = r.verifyBlock != 0 && captureKey == RemoteKeys.captureKey(sk, r.verifyBlock, r.verifyHash);
        bool onSnapshot = !pass && captureKey == RemoteKeys.captureKey(sk, 0, bytes32(0));
        if (r.verdict != VERDICT_NONE || r.snapshotBlock == 0 || !(onCapture || onSnapshot)) {
            emit SettleIgnored(kernel, jobId, captureKey);
            return;
        }
        r.verdict = pass ? VERDICT_PASS : VERDICT_FAIL;
        r.reason = reason;
        emit VerdictRecorded(kernel, jobId, captureKey, pass, reason);
        (bool ok, bytes memory err) = _apply(kernel, jobId, r);
        if (!ok) emit ApplyFailed(kernel, jobId, err);
    }

    // ═════════════════════════════════ views ═════════════════════════════════

    function recordOf(address kernel, uint256 jobId) external view returns (Record memory) {
        return _records[kernel][jobId];
    }

    /// @notice The key Push files this job under; zero until `snapshot`.
    function snapshotKeyOf(address kernel, uint256 jobId) external view returns (bytes32) {
        Record storage r = _records[kernel][jobId];
        if (r.snapshotBlock == 0) return bytes32(0);
        return _snapshotKey(kernel, jobId, r);
    }

    /// @notice The key the verdict must carry; zero until `verify`.
    function captureKeyOf(address kernel, uint256 jobId) external view returns (bytes32) {
        Record storage r = _records[kernel][jobId];
        if (r.verifyBlock == 0) return bytes32(0);
        return _captureKey(kernel, jobId, r);
    }

    /// @notice The InboundSender for one of a job's inbounds (deployed on its first use).
    function senderOf(address kernel, uint256 jobId, uint32 slot) public view returns (address) {
        return RemoteKeys.senderOf(address(this), kernel, jobId, slot, senderCodeHash());
    }

    /// @notice keccak256 of the InboundSender creation code this gateway deploys. The RemoteEvaluator is given the same
    ///         value for this chain, to recognise the senders' UEAs.
    function senderCodeHash() public pure returns (bytes32) {
        return keccak256(type(InboundSender).creationCode);
    }

    /// @notice A job read through its kernel's layout.
    function jobOf(address kernel, uint256 jobId) external view returns (RemoteJob memory) {
        return _job(kernel, jobId);
    }

    /// @notice Reverts unless `description` is criteria this gateway can judge. For clients to check before funding.
    function checkSpec(bytes calldata description) external view {
        _checkSpec(description);
    }

    // ═════════════════════════════════ internal ═════════════════════════════════

    /// @dev Reads a job through its kernel's layout. Reverts for an unlisted kernel or a job that doesn't exist.
    function _job(address kernel, uint256 jobId) internal view returns (RemoteJob memory j) {
        uint8 layout = layoutOf[kernel];
        if (layout == LAYOUT_V) {
            IKernelLayoutV.JobV memory v = IKernelLayoutV(kernel).getJob(jobId);
            j = RemoteJob({
                client: v.client,
                provider: v.provider,
                evaluator: v.evaluator,
                hook: v.hook,
                status: v.status,
                expiredAt: v.expiredAt,
                description: v.description
            });
        } else if (layout == LAYOUT_R) {
            IKernelLayoutR.JobR memory x = IKernelLayoutR(kernel).getJob(jobId);
            j = RemoteJob({
                client: x.client,
                provider: x.provider,
                evaluator: x.evaluator,
                hook: x.hook,
                status: x.status,
                // forge-lint: disable-next-line(unsafe-typecast)
                expiredAt: x.expiredAt > type(uint64).max ? type(uint64).max : uint64(x.expiredAt), // safe: capped
                description: x.description
            });
        } else {
            revert EvaluationGatewayErrors.UnsupportedKernel(kernel);
        }
        if (j.client == address(0)) revert EvaluationGatewayErrors.UnknownJob(kernel, jobId);
    }

    /// @dev The hook rule and the criteria rules. Returns the decoded criteria.
    function _checkJob(RemoteJob memory job) internal view returns (JobSpec memory) {
        if (job.hook != address(0) && job.hook != NOOP_HOOK) revert EvaluationGatewayErrors.HookNotAllowed(job.hook);
        return _checkSpec(bytes(job.description));
    }

    /// @dev Decodes (reverting on bytes that are not a `JobSpec`) and runs `JobSpecLib.validate`. Reads on other EVM
    ///      chains are allowed; whether Push serves a chain is checked on Push, where its tracked height lives. A
    ///      `POST_AT_VERIFY` read must be on this chain: this gateway reads it.
    function _checkSpec(bytes memory description) internal view returns (JobSpec memory s) {
        if (description.length > MAX_DESCRIPTION_LENGTH) revert JobSpecErrors.SpecTooLong(description.length);
        s = abi.decode(description, (JobSpec));
        JobSpecLib.validate(s, MAX_CONFIRMATIONS, true);
        bytes32 here = keccak256(bytes(Strings.toString(block.chainid)));
        for (uint256 i; i < s.reads.length; ++i) {
            if (s.reads[i].at == ReadAt.POST_AT_VERIFY && keccak256(bytes(s.reads[i].chainId)) != here) {
                revert EvaluationGatewayErrors.ReadNotHere(i);
            }
        }
    }

    /// @dev One read, here: `target.staticcall(selector ‖ args)` with exactly `READ_GAS`. The answer is what Read State
    ///      would deliver for the same call: the raw return data, or empty bytes when it reverts. An answer longer
    ///      than `MAX_RESULT_LENGTH` is unreadable on Push anyway, so it is not copied.
    ///      Refuses to run unless the call can get all of `READ_GAS` (the 63/64 rule), so no caller can starve a read
    ///      into an empty answer.
    function _readHere(Read memory r) internal view returns (bytes memory out) {
        uint256 g = READ_GAS;
        uint256 needed = g + g / 63 + READ_OVERHEAD;
        if (gasleft() < needed) revert EvaluationGatewayErrors.ReadGasTooLow(gasleft(), needed);
        bytes memory data = abi.encodePacked(r.selector, r.args);
        address target = r.target;
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(g, target, add(data, 32), mload(data), 0, 0)
            size := returndatasize()
        }
        if (!ok || size > MAX_RESULT_LENGTH) return out;
        out = new bytes(size);
        assembly ("memory-safe") {
            returndatacopy(add(out, 32), 0, size)
        }
    }

    function _checkCapture(Record storage r, bytes calldata spec, bytes[] calldata preResults) internal view {
        if (keccak256(spec) != r.specHash) revert EvaluationGatewayErrors.SpecMismatch();
        if (keccak256(abi.encode(preResults)) != r.preHash) revert EvaluationGatewayErrors.PreResultsMismatch();
    }

    function _snapshotKey(address kernel, uint256 jobId, Record storage r) internal view returns (bytes32) {
        return RemoteKeys.snapshotKey(
            Strings.toString(block.chainid), kernel, jobId, r.specHash, r.preHash, r.snapshotBlock
        );
    }

    function _captureKey(address kernel, uint256 jobId, Record storage r) internal view returns (bytes32) {
        return RemoteKeys.captureKey(_snapshotKey(kernel, jobId, r), r.verifyBlock, r.verifyHash);
    }

    /// @dev One of the job's inbounds to Push: the snapshot (`verifyBlock` 0) or the verify, paid by the caller.
    function _sendJob(
        address kernel,
        uint256 jobId,
        uint32 slot,
        uint64 verifyBlock,
        bytes calldata spec,
        bytes[] calldata preResults,
        bytes[] memory verifyResults,
        PushFees calldata fees
    ) internal {
        uint64 snapshotBlock = _records[kernel][jobId].snapshotBlock;
        bytes memory call = abi.encodeCall(
            IRemoteEvaluator.onRemoteJob,
            (kernel, jobId, msg.sender, spec, preResults, snapshotBlock, verifyBlock, verifyResults)
        );
        _send(kernel, jobId, slot, call, fees);
    }

    /// @dev One GAS_AND_PAYLOAD inbound, sent through the slot's InboundSender (deployed here on first use): `msg.value`
    ///      is the gas, swapped into PC for the sender's UEA on Push, which then calls the RemoteEvaluator with
    ///      `fees.pcForJob`. Each sender sends one message, so its payload nonce is always 0. The caller paid, so the
    ///      payload names it as the payer: Push refunds what the job doesn't spend to its UEA. A swap that fails
    ///      returns the native to the caller.
    function _send(address kernel, uint256 jobId, uint32 slot, bytes memory call, PushFees calldata fees) internal {
        if (msg.value == 0) revert EvaluationGatewayErrors.NoGasSent();
        if (fees.gasLimit == 0 || fees.maxFeePerGas == 0) revert EvaluationGatewayErrors.BadPushFees();
        address sender = senderOf(kernel, jobId, slot);
        if (sender.code.length == 0) {
            new InboundSender{salt: RemoteKeys.senderSalt(kernel, jobId, slot)}();
        }
        UniversalPayload memory p = UniversalPayload({
            to: REMOTE_EVALUATOR,
            value: fees.pcForJob,
            data: call,
            gasLimit: fees.gasLimit,
            maxFeePerGas: fees.maxFeePerGas,
            maxPriorityFeePerGas: 0,
            nonce: 0,
            deadline: 0,
            vType: VerificationType.universalTxVerification
        });
        InboundSender(sender).send{value: msg.value}(
            address(UGW),
            abi.encodeCall(
                IUniversalGateway.sendUniversalTx,
                (UniversalTxRequest({
                        recipient: address(0),
                        token: address(0),
                        amount: 0,
                        payload: abi.encode(p),
                        revertRecipient: msg.sender,
                        signatureData: ""
                    }))
            )
        );
        // forge-lint: disable-next-line(unsafe-typecast)
        emit InboundSent(kernel, jobId, slot, sender, bytes4(call), msg.value, fees.pcForJob); // safe: the selector
    }

    /// @dev The CEA is looked up now, through the factory the Vault uses: a CEA address worked out before the CEA
    ///      exists can change (the factory's implementation and the gateway's factory are both settable).
    function _requireEvaluatorCEA() internal view {
        address factory = IVaultCEAFactory(IUniversalGatewayVault(address(UGW)).VAULT()).CEAFactory();
        if (ICEAFactory(factory).getPushAccountForCEA(msg.sender) != REMOTE_EVALUATOR) {
            revert EvaluationGatewayErrors.NotEvaluatorCEA(msg.sender);
        }
    }

    /// @dev PASS completes, FAIL rejects. Returns the kernel's revert data if it refused.
    function _apply(address kernel, uint256 jobId, Record storage r) internal returns (bool ok, bytes memory err) {
        bool pass = r.verdict == VERDICT_PASS;
        bytes4 action = pass ? IKernelVerdict.complete.selector : IKernelVerdict.reject.selector;
        (ok, err) = kernel.call(abi.encodeWithSelector(action, jobId, r.reason, bytes("")));
        if (ok) {
            r.applied = true;
            emit VerdictApplied(kernel, jobId, pass);
        }
    }
}
