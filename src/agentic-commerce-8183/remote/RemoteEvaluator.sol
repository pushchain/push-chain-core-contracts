// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IUEAFactory} from "../../interfaces/IUEAFactory.sol";
import {IUniversalCallback} from "../../interfaces/IUniversalCallback.sol";
import {UniversalAccountId} from "../../libraries/Types.sol";
import {RequestStatus, MAX_CALLBACK_GAS_LIMIT} from "../../libraries/ReadTypes.sol";
import {JobSpec, Read, Check, ReadAt} from "../libraries/JobSpecTypes.sol";
import {JobSpecErrors} from "../libraries/Errors.sol";
import {JobSpecLib} from "../evaluator/JobSpecLib.sol";
import {EvmReadLib, FireParams} from "../evaluator/EvmReadLib.sol";
import {
    Answer,
    Verdict,
    OwnerCheck,
    ReadConfig,
    IReadStateViews,
    MAX_RESULT_LENGTH,
    MAX_DESCRIPTION_LENGTH
} from "../evaluator/EvaluationTypes.sol";
import {
    RemoteKeys,
    SNAPSHOT_SLOT,
    VERIFY_SLOT,
    UniversalOutboundTxRequest,
    IUniversalGatewayPC,
    IRemoteCore,
    IReadStateModule,
    IRemoteEvaluator,
    IEvaluationGateway,
    RemoteEvaluatorErrors
} from "./RemoteTypes.sol";

/// @title RemoteEvaluator — judges, on Push, jobs that live on kernels on other chains
/// @notice Each remote chain has one EvaluationGateway, fixed in `initialize`. A job reaches this contract from that
///         gateway (`onRemoteJob`), filed under its snapshot key, in up to two inbounds:
///         - the snapshot, sent only when the criteria have PRE reads on other chains: Push's fresh tracked height is
///           recorded for every read on another chain (a PRE read's block, a POST read's floor) and the PRE reads go
///           to Read State. The provider starts work after `SnapshotReady`;
///         - the verify: E (the block of the provider's `verify`) and the values the gateway read inside it
///           (`POST_AT_VERIFY`).
///         The rest is read through Read State: POST reads on the gateway's chain at E once Push tracks E, POST reads
///         on another chain at Push's fresh tracked height when the verify inbound runs (above the one recorded at the
///         snapshot, when the snapshot sent an inbound). A callback stores
///         only the answer's hash. `sendVerdict` takes the criteria and the raw answers (each must match its hash),
///         decodes and judges them with the Phase 1 functions, and sends the verdict once the root is decided.
///         When the values the gateway supplied already decide the root (every POST read `POST_AT_VERIFY`, for
///         instance), the verdict is worked out and sent inside the verify inbound itself.
/// @dev - Judged when sent, not in a callback: a verdict can't leave from a Read State callback (callbacks never create
///        outbounds), so a transaction after the answers is needed anyway; judging there keeps callbacks to one hash.
///        `sendReads` and `sendVerdict` refuse to run inside any callback (`tx.origin` is then the callback module).
///      - Same rules as the UniversalEvaluator: every tracked height used is at most `MAX_HEIGHT_AGE` old; a POST read
///        on another chain is read above the height recorded for it at the start; a read Read State blocks, or on a
///        chain Push does not track, ends the job at once (here a FAIL, sent from that inbound, since the job is
///        already funded); the evidence and `reason` have the same layout; one evaluation, blocks fixed once, retries
///        at the same block. An answered read is final: re-reading it would read the same block.
///      - Refunds go to whoever paid, not always to the client as in Phase 1, where the client prefunds everything.
///        Here the client pays the snapshot inbound and the provider (or whoever resends it) the verify inbound, which
///        funds the POST reads and the verdict. So unspent PC, callback budgets and outbound gas go to the UEA of
///        whoever paid the job's latest inbound.
///      - The gateway sends each inbound through its own InboundSender (CREATE2 for one job and slot), so each runs
///        from its own UEA with nonce 0. The caller must be the UEA of the sender for this job and inbound: its origin
///        names a registered chain and, as owner, the address the chain's gateway deploys that sender at.
///      - The chain comes from the caller's UEA origin, never from the payload. The snapshot key commits to the chain,
///        the job, the criteria, the PRE answers read on the gateway's chain and S; the verdict carries the capture
///        key, which adds E and the `POST_AT_VERIFY` answers, and the gateway applies only its own.
///      - PC: each job's PC comes in with its inbounds (`pcForJob`) or through `fund`. It pays the job's reads and its
///        first verdict outbound. A later verdict outbound is paid by its caller, who gets the surplus back.
///      - Behind a TransparentUpgradeableProxy while testing, with settings written once in `initialize` and no
///        setter. The UniversalEvaluator is not upgradeable; before mainnet this contract becomes the same (or
///        timelocked): whoever can upgrade it can send any verdict to every gateway.
contract RemoteEvaluator is IRemoteEvaluator, Initializable, ReentrancyGuard {
    /// @notice A remote chain, as `initialize` takes it.
    struct Remote {
        string chainId; // decimal EIP-155 id, as the UEA origin carries it
        address gateway; // the EvaluationGateway proxy on that chain
        uint64 settleGasLimit; // outbound gas limit for `settle`, at least the chain's base limit
        bytes32 senderCodeHash; // the gateway's `senderCodeHash()`
    }

    struct Config {
        address ueaFactory;
        address universalGatewayPC;
        address readState; // UniversalCallback
        address universalCore;
        ReadConfig read;
        Remote[] remotes;
    }

    /// @notice One job.
    struct Job {
        address kernel; // on the remote chain
        uint64 snapshotBlock; // S; non-zero once registered
        uint64 verifyBlock; // E; non-zero once the provider verified
        uint256 jobId;
        string chainId; // the gateway's chain
        address payer; // the UEA of whoever paid the job's latest inbound: unspent PC, callback budgets, outbound gas
        bytes32 specHash;
        bytes32 captureKey; // the verdict carries it
        bytes32 reason; // set with the verdict
        uint8 reads;
        bool verdictSent; // the first verdict outbound went out, paid from the job's PC
        Verdict verdict; // NONE until worked out
        uint32 pre; // bit i: read i is PRE
        uint32 cross; // bit i: read i is on another chain
        uint32 supplied; // bit i: the gateway read it (PRE at S, or `POST_AT_VERIFY` inside `verify`)
        uint32 answered; // bit i: read i has an answer
        uint256 prepaid; // unspent PC
    }

    struct RequestRef {
        bytes32 key;
        uint8 read;
    }

    // ───────── events ─────────

    event JobRegistered(bytes32 indexed key, address kernel, uint256 jobId, uint64 snapshotBlock);
    event CaptureRecorded(bytes32 indexed key, bytes32 captureKey, uint64 verifyBlock);
    event Funded(bytes32 indexed key, address indexed from, uint256 amount);
    event ReadsSent(bytes32 indexed key, uint256 reads, uint256 paid);
    /// @notice Inside an inbound, the reads that were due or the first verdict send failed; `sendReads` or
    ///         `sendVerdict` sends them later.
    event SendFailed(bytes32 indexed key, bytes reason);
    event ReadAnswered(bytes32 indexed key, uint8 indexed read, uint256 requestId, bytes32 resultHash);
    event SnapshotReady(bytes32 indexed key);
    event VerdictReady(bytes32 indexed key, Verdict verdict, bytes32 reason);
    event VerdictSent(bytes32 indexed key, bool pass, uint256 paid);
    event PrepaidRefunded(bytes32 indexed key, address indexed to, uint256 amount);

    /// @notice Gas for one decode, run as a capped self-call so a bad answer can't consume the call.
    uint256 internal constant DECODE_GAS = 200_000;

    // ───────── configuration, written once in `initialize` ─────────

    IUEAFactory public UEA_FACTORY;
    IUniversalGatewayPC public UGPC;
    IUniversalCallback public READ_STATE;
    IRemoteCore public UNIVERSAL_CORE;
    /// @notice The module account Read State runs every callback as; `tx.origin` inside any callback.
    address public CALLBACK_MODULE;
    uint64 public READ_TTL;
    uint64 public CALLBACK_GAS_LIMIT;
    uint64 public SNAPSHOT_CALLBACK_GAS_LIMIT;
    uint256 public BUDGET_MULTIPLIER;
    uint256 public MAX_HEIGHT_AGE;
    uint16 public MAX_CONFIRMATIONS;
    /// @notice The EvaluationGateway on each remote chain, by decimal chain id.
    mapping(string => address) public gatewayOf;
    mapping(string => uint64) public settleGasOf;
    mapping(string => bytes32) public senderCodeHashOf;

    // ───────── storage ─────────

    mapping(bytes32 => Job) internal _jobs;
    mapping(bytes32 => mapping(uint256 => bytes32)) internal _resultHash; // key => read => keccak256(raw answer)
    mapping(bytes32 => mapping(uint256 => uint256)) internal _request; // key => read => current request
    mapping(uint256 => RequestRef) internal _requests;
    mapping(bytes32 => uint256[8]) internal _heights; // each read's block, 4 uint64 per word; 0 until fixed
    mapping(bytes32 => uint256[8]) internal _floors; // a read on another chain: Push's tracked height at the snapshot

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(Config calldata c) external initializer {
        if (
            c.ueaFactory == address(0) || c.universalGatewayPC == address(0) || c.readState == address(0)
                || c.universalCore == address(0) || c.remotes.length == 0
        ) revert RemoteEvaluatorErrors.ZeroValue();
        ReadConfig calldata rc = c.read;
        if (
            rc.readTtl == 0 || rc.callbackGasLimit == 0 || rc.callbackGasLimit > MAX_CALLBACK_GAS_LIMIT
                || rc.snapshotCallbackGasLimit == 0 || rc.snapshotCallbackGasLimit > MAX_CALLBACK_GAS_LIMIT
                || rc.budgetMultiplier == 0 || rc.maxHeightAge == 0 || rc.maxConfirmations == 0
        ) revert RemoteEvaluatorErrors.ZeroValue();
        UEA_FACTORY = IUEAFactory(c.ueaFactory);
        UGPC = IUniversalGatewayPC(c.universalGatewayPC);
        READ_STATE = IUniversalCallback(c.readState);
        UNIVERSAL_CORE = IRemoteCore(c.universalCore);
        CALLBACK_MODULE = IReadStateModule(c.readState).UNIVERSAL_CALLBACK_MODULE();
        if (CALLBACK_MODULE == address(0)) revert RemoteEvaluatorErrors.ZeroValue();
        READ_TTL = rc.readTtl;
        CALLBACK_GAS_LIMIT = rc.callbackGasLimit;
        SNAPSHOT_CALLBACK_GAS_LIMIT = rc.snapshotCallbackGasLimit;
        BUDGET_MULTIPLIER = rc.budgetMultiplier;
        MAX_HEIGHT_AGE = rc.maxHeightAge;
        MAX_CONFIRMATIONS = rc.maxConfirmations;
        for (uint256 i; i < c.remotes.length; ++i) {
            Remote calldata r = c.remotes[i];
            if (
                bytes(r.chainId).length == 0 || r.gateway == address(0) || r.settleGasLimit == 0
                    || r.senderCodeHash == bytes32(0)
            ) revert RemoteEvaluatorErrors.ZeroValue();
            if (gatewayOf[r.chainId] != address(0)) revert RemoteEvaluatorErrors.DuplicateChain(r.chainId);
            gatewayOf[r.chainId] = r.gateway;
            settleGasOf[r.chainId] = r.settleGasLimit;
            senderCodeHashOf[r.chainId] = r.senderCodeHash;
        }
    }

    // ═════════════════════════════════ from a gateway ═════════════════════════════════

    /// @inheritdoc IRemoteEvaluator
    /// @dev Only from the UEA of the gateway's sender for this job and inbound. One entry for the job's two inbounds:
    ///      - the snapshot (`verifyBlock == 0`): registers the job and pins its reads on other chains;
    ///      - the verify: registers the job if the snapshot did not, records E and the `POST_AT_VERIFY` answers, and
    ///        works out the verdict right away if those answers and the gateway's PRE answers decide it. A job with
    ///        PRE reads on other chains must have its snapshot in first, because those heights are fixed there,
    ///        before the work; otherwise this reverts and the gateway sends it again later.
    ///      Then whatever can be sent goes out, in a guarded call; the rest waits for `sendReads` / `sendVerdict`.
    function onRemoteJob(
        address kernel,
        uint256 jobId,
        address payer,
        bytes calldata spec,
        bytes[] calldata preResults,
        uint64 snapshotBlock,
        uint64 verifyBlock,
        bytes[] calldata verifyResults
    ) external payable nonReentrant {
        string memory chainId = _gatewayChain(kernel, jobId, verifyBlock == 0 ? SNAPSHOT_SLOT : VERIFY_SLOT);
        if (snapshotBlock == 0 || (verifyBlock != 0 && verifyBlock <= snapshotBlock)) {
            revert RemoteEvaluatorErrors.BadBlocks(snapshotBlock, verifyBlock);
        }
        bytes32 key = RemoteKeys.snapshotKey(
            chainId, kernel, jobId, keccak256(spec), keccak256(abi.encode(preResults)), snapshotBlock
        );
        Job storage j = _jobs[key];
        _addPrepaid(key, j);
        j.payer = UEA_FACTORY.computeUEA(
            UniversalAccountId({chainNamespace: "eip155", chainId: chainId, owner: abi.encodePacked(payer)})
        );
        if (j.snapshotBlock == 0) {
            _register(key, j, chainId, kernel, jobId, spec, preResults, snapshotBlock, verifyBlock == 0);
            if (verifyBlock != 0 && j.verdict == Verdict.NONE && j.answered & j.pre != j.pre) {
                revert RemoteEvaluatorErrors.SnapshotNotRegistered(key);
            }
        }
        if (verifyBlock != 0 && j.verifyBlock == 0 && j.verdict == Verdict.NONE) {
            _recordVerify(key, j, spec, verifyBlock, verifyResults);
            _judge(key, j, spec, preResults, verifyResults, true); // decides now if the supplied answers suffice
        }
        try this.advance(key, spec) {}
        catch (bytes memory err) {
            emit SendFailed(key, err);
        }
    }

    /// @notice The guarded half of `onRemoteJob`, as its own call so a failure to send keeps what was recorded: the
    ///         first verdict outbound if the verdict is decided, otherwise the reads that are due.
    function advance(bytes32 key, bytes calldata spec) external {
        if (msg.sender != address(this)) revert RemoteEvaluatorErrors.CallerIsNotSelf(msg.sender);
        Job storage j = _jobs[key];
        if (j.verdict == Verdict.NONE) _sendDue(key, j, _decodeSpec(spec));
        else if (j.verdict != Verdict.INCONCLUSIVE && !j.verdictSent) _firstSend(key, j);
    }

    // ═════════════════════════════════ anyone ═════════════════════════════════

    /// @inheritdoc IRemoteEvaluator
    /// @notice Sends the job's reads that are due and not in flight: PRE reads on other chains until each has an
    ///         answer; then, once E is known, the POST reads (on the gateway's chain once Push tracks E). Never-sent,
    ///         expired or failed requests go again at the same block. `msg.value` is added to the job's PC. Never from
    ///         inside a callback.
    /// @dev Never fixes a block (the snapshot and the verify inbounds do), so anyone may call it: whoever does can't
    ///      choose when the job is measured.
    /// @param spec The job's criteria (its description on the remote chain), checked against the frozen hash.
    function sendReads(bytes32 key, bytes calldata spec) external payable nonReentrant {
        _notInCallback();
        Job storage j = _jobs[key];
        if (j.snapshotBlock == 0) revert RemoteEvaluatorErrors.UnknownJob(key);
        if (keccak256(spec) != j.specHash) revert RemoteEvaluatorErrors.SpecMismatch(key);
        if (j.verdict != Verdict.NONE) revert RemoteEvaluatorErrors.NothingToSend(key);
        _addPrepaid(key, j);
        _sendDue(key, j, _decodeSpec(spec));
    }

    /// @inheritdoc IRemoteEvaluator
    /// @notice Works out the verdict if it isn't yet, and sends a PASS or FAIL to the job's gateway. Never from inside
    ///         a callback.
    ///         - To work it out, give the job's criteria, the PRE answers the gateway read at S, and every answered
    ///           read's raw answer (`ReadFulfilled` data, or the `verify` answers). It reverts with `NotDecided` while
    ///           the root depends on answers still out; once every read is answered and the root is still unknown, the
    ///           verdict is INCONCLUSIVE and nothing is sent.
    ///         - The first send is paid from the job's PC (plus `msg.value`); the surplus comes back to the job.
    ///         - A later send (a failed outbound reports nothing back to Push; the gateway ignores every copy after the
    ///           first) is paid by its caller with `msg.value`, and the surplus goes back to the caller; the bytes are
    ///           not needed then. So nobody can spend a job's PC by sending its verdict again and again.
    function sendVerdict(bytes32 key, bytes calldata spec, bytes[] calldata preResults, bytes[] calldata results)
        external
        payable
        nonReentrant
    {
        _notInCallback();
        Job storage j = _jobs[key];
        if (j.snapshotBlock == 0) revert RemoteEvaluatorErrors.UnknownJob(key);
        if (j.verdict == Verdict.NONE) {
            if (j.verifyBlock == 0 || _judge(key, j, spec, preResults, results, false) == Verdict.NONE) {
                revert RemoteEvaluatorErrors.NotDecided(key);
            }
            if (j.verdict == Verdict.INCONCLUSIVE) {
                _addPrepaid(key, j);
                return;
            }
        }
        if (j.verdict == Verdict.INCONCLUSIVE) revert RemoteEvaluatorErrors.NoVerdict(key);
        if (!j.verdictSent) {
            _addPrepaid(key, j);
            _firstSend(key, j);
        } else {
            if (msg.value == 0) revert RemoteEvaluatorErrors.ResendUnpaid(key);
            _pay(msg.sender, _sendOutbound(key, j, msg.value, msg.sender));
        }
    }

    /// @notice Adds PC to a job.
    function fund(bytes32 key) external payable {
        Job storage j = _jobs[key];
        if (j.snapshotBlock == 0) revert RemoteEvaluatorErrors.UnknownJob(key);
        _addPrepaid(key, j);
    }

    /// @notice Sends the job's unspent PC to its payer's UEA (whoever paid the job's latest inbound): whenever the payer
    ///         asks, and from anyone once nothing more is paid from it (the verdict was sent, or it is INCONCLUSIVE).
    ///         Taking it early only leaves the payer's own reads or verdict to be paid again by whoever sends them.
    function claimPrepaid(bytes32 key) external nonReentrant {
        Job storage j = _jobs[key];
        if (msg.sender != j.payer && !j.verdictSent && j.verdict != Verdict.INCONCLUSIVE) {
            revert RemoteEvaluatorErrors.NotClaimable(key);
        }
        uint256 amount = j.prepaid;
        j.prepaid = 0;
        _pay(j.payer, amount);
        emit PrepaidRefunded(key, j.payer, amount);
    }

    /// @notice Takes back the PC surplus `UniversalGatewayPC` refunds in the same call.
    receive() external payable {}

    // ═════════════════════════════════ callback ═════════════════════════════════

    /// @notice Read State delivers one answer: its hash is stored. Nothing is decoded, judged, sent or requested here.
    function onUniversalData(uint256 requestId, bytes calldata result) external {
        if (msg.sender != address(READ_STATE)) revert RemoteEvaluatorErrors.CallerIsNotReadState(msg.sender);
        RequestRef memory q = _requests[requestId];
        if (q.key == bytes32(0)) return;
        delete _requests[requestId];
        bytes32 key = q.key;
        uint8 read = q.read;
        if (_request[key][read] != requestId) return; // superseded by a re-send
        Job storage j = _jobs[key];
        if (j.verdict != Verdict.NONE || (j.answered >> read) & 1 == 1) return;
        bytes32 h = keccak256(result);
        _resultHash[key][read] = h;
        j.answered |= uint32(1) << read;
        emit ReadAnswered(key, read, requestId, h);
        if ((j.pre >> read) & 1 == 1 && j.answered & j.pre == j.pre) emit SnapshotReady(key);
    }

    // ═════════════════════════════════ views ═════════════════════════════════

    /// @notice The number to compare, from one answer. Pure; this contract calls it on itself with a gas cap.
    function decodeAnswer(bytes calldata outputs, uint8[] calldata field, bytes calldata res)
        external
        pure
        returns (bool, int256)
    {
        return EvmReadLib.decode(outputs, field, res);
    }

    /// @notice A job's state, without its chain id or per-read data (`readOf`).
    function jobOf(bytes32 key)
        external
        view
        returns (
            uint64 snapshotBlock,
            uint64 verifyBlock,
            bytes32 captureKey,
            bool verdictSent,
            Verdict verdict,
            bytes32 reason,
            uint32 answered,
            uint256 prepaid
        )
    {
        Job storage j = _jobs[key];
        return (j.snapshotBlock, j.verifyBlock, j.captureKey, j.verdictSent, j.verdict, j.reason, j.answered, j.prepaid);
    }

    /// @notice One read: the block it is read at (0 until fixed), its current Read State request (0 for an answer the
    ///         gateway supplied) and the hash of its answer (0 until answered; for a PRE read the gateway took at S,
    ///         bound by the snapshot key instead).
    function readOf(bytes32 key, uint256 read) external view returns (uint64 height, uint256 requestId, bytes32 resultHash) {
        return (_height(_heights[key], read), _request[key][read], _resultHash[key][read]);
    }

    // ═════════════════════════════════ internal ═════════════════════════════════

    /// @dev The caller must be the UEA whose owner is the InboundSender a registered gateway sends this job's `slot`
    ///      inbound through; returns that gateway's chain id.
    function _gatewayChain(address kernel, uint256 jobId, uint32 slot) internal view returns (string memory) {
        (UniversalAccountId memory o, bool isUEA) = UEA_FACTORY.getOriginForUEA(msg.sender);
        if (!isUEA || keccak256(bytes(o.chainNamespace)) != EvmReadLib.EVM_NAMESPACE_HASH || o.owner.length != 20) {
            revert RemoteEvaluatorErrors.NotGateway(msg.sender);
        }
        address gateway = gatewayOf[o.chainId];
        if (
            gateway == address(0)
                || address(bytes20(o.owner))
                    != RemoteKeys.senderOf(gateway, kernel, jobId, slot, senderCodeHashOf[o.chainId])
        ) revert RemoteEvaluatorErrors.NotGateway(msg.sender);
        return o.chainId;
    }

    /// @dev Inside a Read State callback `tx.origin` is the callback module.
    function _notInCallback() internal view {
        // solhint-disable-next-line avoid-tx-origin
        if (tx.origin == CALLBACK_MODULE) revert RemoteEvaluatorErrors.InsideCallback();
    }

    function _decodeSpec(bytes memory spec) internal pure returns (JobSpec memory) {
        return abi.decode(spec, (JobSpec));
    }

    /// @dev Checks and files the criteria. PRE reads on the gateway's chain count as answered: the gateway read them at
    ///      S (bound by the snapshot key). At the snapshot (before the work), Push's fresh tracked height is recorded for
    ///      every read on another chain: a PRE read's block, a POST read's floor. A read on a chain Read State blocks or
    ///      Push does not track decides FAIL.
    function _register(
        bytes32 key,
        Job storage j,
        string memory chainId,
        address kernel,
        uint256 jobId,
        bytes calldata spec,
        bytes[] calldata preResults,
        uint64 snapshotBlock,
        bool atSnapshot
    ) internal {
        if (spec.length > MAX_DESCRIPTION_LENGTH) revert JobSpecErrors.SpecTooLong(spec.length);
        JobSpec memory s = _decodeSpec(spec);
        JobSpecLib.validate(s, MAX_CONFIRMATIONS, true);
        uint256 n = s.reads.length;
        if (preResults.length != n) revert RemoteEvaluatorErrors.ResultsLength(preResults.length, n);

        j.kernel = kernel;
        j.jobId = jobId;
        j.chainId = chainId;
        j.specHash = keccak256(spec);
        j.snapshotBlock = snapshotBlock;
        // forge-lint: disable-next-line(unsafe-typecast)
        j.reads = uint8(n); // safe: JobSpecLib caps reads at MAX_READS (32)
        emit JobRegistered(key, kernel, jobId, snapshotBlock);

        bytes32 here = keccak256(bytes(chainId));
        bool fail;
        for (uint256 i; i < n; ++i) {
            Read memory r = s.reads[i];
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 bit = uint32(1 << i); // safe: i < MAX_READS (32)
            bool pre = r.at == ReadAt.PRE_EXECUTION;
            if (pre) j.pre |= bit;
            if (keccak256(bytes(r.chainId)) == here) {
                if (pre) {
                    j.supplied |= bit;
                    j.answered |= bit;
                    _setHeight(_heights[key], i, snapshotBlock);
                } else if (preResults[i].length != 0) {
                    revert RemoteEvaluatorErrors.SuppliedWrongRead(i);
                }
                continue;
            }
            j.cross |= bit;
            if (preResults[i].length != 0) revert RemoteEvaluatorErrors.SuppliedWrongRead(i);
            if (r.at == ReadAt.POST_AT_VERIFY) revert RemoteEvaluatorErrors.ReadNotOnGatewayChain(i);
            if (
                IReadStateViews(address(READ_STATE)).isDomainBlocked(r.chainNamespace, r.chainId)
                    || UNIVERSAL_CORE.chainHeightByChainNamespace(EvmReadLib.chainKey(r)) == 0
            ) {
                fail = true;
            } else if (atSnapshot) {
                uint64 h = EvmReadLib.latestHeight(UNIVERSAL_CORE, r, MAX_HEIGHT_AGE);
                _setHeight(_floors[key], i, h);
                if (pre) _setHeight(_heights[key], i, h);
            }
        }
        if (fail) {
            // Never answerable: FAIL now, so the client is refunded at once instead of at expiry. Its capture key has
            // no E, and the gateway takes it as a FAIL whether or not the provider has verified.
            j.captureKey = RemoteKeys.captureKey(key, 0, bytes32(0));
            _decide(key, j, Verdict.FAIL, new bytes32[](n));
        } else if (j.answered & j.pre == j.pre) {
            emit SnapshotReady(key);
        }
    }

    /// @dev Records E and the answers the gateway read inside `verify`, and fixes every POST read's block, as the
    ///      UniversalEvaluator does at `submit`: on the gateway's chain E; on another chain Push's fresh tracked height,
    ///      which must be above the one recorded at the snapshot, or this reverts and the provider sends the verify
    ///      again later. Nothing fixes a block after this, so nobody else chooses when the job is measured.
    function _recordVerify(
        bytes32 key,
        Job storage j,
        bytes calldata spec,
        uint64 verifyBlock,
        bytes[] calldata verifyResults
    ) internal {
        JobSpec memory s = _decodeSpec(spec);
        uint256 n = s.reads.length;
        if (verifyResults.length != n) revert RemoteEvaluatorErrors.ResultsLength(verifyResults.length, n);
        for (uint256 i; i < n; ++i) {
            if (s.reads[i].at == ReadAt.POST_AT_VERIFY) {
                _resultHash[key][i] = keccak256(verifyResults[i]);
                // forge-lint: disable-next-line(unsafe-typecast)
                uint32 bit = uint32(1 << i); // safe: i < MAX_READS (32)
                j.supplied |= bit;
                j.answered |= bit;
                _setHeight(_heights[key], i, verifyBlock);
            } else {
                if (verifyResults[i].length != 0) revert RemoteEvaluatorErrors.SuppliedWrongRead(i);
                if ((j.pre >> i) & 1 == 1) continue; // a PRE read's block was fixed at the snapshot
                if ((j.cross >> i) & 1 == 0) {
                    _setHeight(_heights[key], i, verifyBlock); // POST on the gateway's chain: E
                    continue;
                }
                uint64 h = EvmReadLib.latestHeight(UNIVERSAL_CORE, s.reads[i], MAX_HEIGHT_AGE);
                uint64 f = _height(_floors[key], i);
                if (h <= f) revert RemoteEvaluatorErrors.HeightNotAfterSnapshot(i, f, h);
                _setHeight(_heights[key], i, h);
            }
        }
        j.verifyBlock = verifyBlock;
        j.captureKey = RemoteKeys.captureKey(key, verifyBlock, keccak256(abi.encode(verifyResults)));
        emit CaptureRecorded(key, j.captureKey, verifyBlock);
    }

    /// @dev PRE reads on other chains until the snapshot is complete; then, with E known, the POST reads Read State
    ///      reads, each at the block already fixed for it. A read on the gateway's chain waits until Push tracks E.
    function _sendDue(bytes32 key, Job storage j, JobSpec memory s) internal {
        bool preDone = j.answered & j.pre == j.pre;
        if (preDone && j.verifyBlock == 0) revert RemoteEvaluatorErrors.AwaitingVerify(key);
        uint256 sent;
        uint256 paid;
        for (uint256 i; i < j.reads; ++i) {
            if (((j.pre >> i) & 1 == 0) != preDone || (j.answered >> i) & 1 == 1) continue;
            uint256 req = _request[key][i];
            if (req != 0 && _inFlight(req)) continue;
            Read memory r = s.reads[i];
            uint64 h = _height(_heights[key], i);
            // on another chain the block is one Push tracked when it was fixed; on the gateway's chain it is S or E
            if ((j.cross >> i) & 1 == 0 && UNIVERSAL_CORE.chainHeightByChainNamespace(EvmReadLib.chainKey(r)) < h) {
                continue;
            }
            uint64 gasLimit = preDone ? CALLBACK_GAS_LIMIT : SNAPSHOT_CALLBACK_GAS_LIMIT;
            uint256 value = _spend(j, EvmReadLib.price(READ_STATE, r, gasLimit, BUDGET_MULTIPLIER));
            uint256 requestId = EvmReadLib.fire(
                READ_STATE,
                r,
                FireParams({
                    owner: j.payer,
                    height: h,
                    value: value,
                    ttl: READ_TTL,
                    revertRecipient: j.payer, // unspent callback budget goes back to whoever paid
                    callbackSelector: this.onUniversalData.selector,
                    callbackGasLimit: gasLimit
                })
            );
            _request[key][i] = requestId;
            // forge-lint: disable-next-line(unsafe-typecast)
            _requests[requestId] = RequestRef({key: key, read: uint8(i)}); // safe: i < 32
            paid += value;
            ++sent;
        }
        if (sent == 0) revert RemoteEvaluatorErrors.NothingToSend(key);
        emit ReadsSent(key, sent, paid);
    }

    /// @dev Decodes every answer it is given, judges every check and the logic (JobSpecLib), and records the verdict
    ///      once the root is decided. Returns NONE while it depends on answers not used here (still out, or, with
    ///      `onlySupplied`, read through Read State). `results[i]` is read i's raw answer; a PRE answer on the gateway's
    ///      chain comes from `preResults`.
    function _judge(
        bytes32 key,
        Job storage j,
        bytes calldata spec,
        bytes[] calldata preResults,
        bytes[] calldata results,
        bool onlySupplied
    ) internal returns (Verdict v) {
        if (keccak256(spec) != j.specHash) revert RemoteEvaluatorErrors.SpecMismatch(key);
        bytes32 sk = RemoteKeys.snapshotKey(
            j.chainId, j.kernel, j.jobId, j.specHash, keccak256(abi.encode(preResults)), j.snapshotBlock
        );
        if (sk != key) revert RemoteEvaluatorErrors.PreResultsMismatch(key);
        uint256 n = j.reads;
        if (results.length != n) revert RemoteEvaluatorErrors.ResultsLength(results.length, n);
        JobSpec memory s = _decodeSpec(spec);

        uint32 used = onlySupplied ? j.answered & j.supplied : j.answered;
        Answer[] memory answers = new Answer[](n);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            if ((used >> i) & 1 == 0) continue; // missing: UNKNOWN, evidence 0
            bool atS = ((j.pre & j.supplied) >> i) & 1 == 1; // read by the gateway at S
            bytes calldata raw = atS ? preResults[i] : results[i];
            if (!atS && keccak256(raw) != _resultHash[key][i]) revert RemoteEvaluatorErrors.ResultMismatch(i);
            bool ok;
            int256 value;
            bytes32 rh;
            if (raw.length <= MAX_RESULT_LENGTH) {
                rh = keccak256(raw);
                try this.decodeAnswer{gas: DECODE_GAS}(s.reads[i].outputs, s.reads[i].field, raw) returns (
                    bool d, int256 val
                ) {
                    (ok, value) = (d, val);
                } catch {}
            }
            answers[i] = Answer({ok: ok, value: value});
            leaves[i] = keccak256(abi.encode(i, _request[key][i], _height(_heights[key], i), rh, ok, value));
        }

        uint32 res;
        for (uint256 c; c < s.checks.length; ++c) {
            Check memory chk = s.checks[c];
            Answer memory b;
            if (chk.right.length != 0) b = _sum(answers, chk.right);
            res = JobSpecLib.setCheck(
                res, c, JobSpecLib.checkResult(chk.evaluation, chk.operation, chk.target, _sum(answers, chk.left), b)
            );
        }
        v = JobSpecLib.verdictPacked(JobSpecLib.packLogic(s.logic), s.logic.length, res);
        uint32 all = n == 32 ? type(uint32).max : uint32((1 << n) - 1);
        if (v == Verdict.INCONCLUSIVE && used != all) return Verdict.NONE;
        _decide(key, j, v, leaves);
    }

    /// @dev Records the verdict and its `reason`, laid out as the UniversalEvaluator's: the job's key (here the capture
    ///      key), the exact spec, every read's evidence in index order, the verdict and the owner check (no wallet to
    ///      check on a remote chain, so UNKNOWN).
    function _decide(bytes32 key, Job storage j, Verdict v, bytes32[] memory leaves) internal {
        j.verdict = v;
        j.reason = keccak256(abi.encode(j.captureKey, j.specHash, leaves, v, OwnerCheck.UNKNOWN));
        emit VerdictReady(key, v, j.reason);
    }

    /// @dev The sum of the reads in `side`: not ok if any is missing or unreadable, or the sum overflows.
    function _sum(Answer[] memory answers, uint8[] memory side) internal pure returns (Answer memory total) {
        total.ok = true;
        for (uint256 k; k < side.length; ++k) {
            Answer memory a = answers[side[k]];
            if (!a.ok) return Answer({ok: false, value: 0});
            (total.ok, total.value) = JobSpecLib.add(total.value, a.value);
            if (!total.ok) return total;
        }
    }

    /// @dev The first verdict outbound, paid from the job's PC; the surplus comes back to the job, and unused gas goes
    ///      to the payer's UEA.
    function _firstSend(bytes32 key, Job storage j) internal {
        uint256 value = j.prepaid;
        if (value == 0) revert RemoteEvaluatorErrors.PrepaidTooLow(1, 0);
        j.prepaid = 0;
        j.verdictSent = true;
        j.prepaid = _sendOutbound(key, j, value, j.payer);
    }

    /// @dev Sends the verdict outbound with `value` PC and returns what `UniversalGatewayPC` refunded in the same call:
    ///      the surplus over the outbound's fees. Unused outbound gas is refunded later to `gasRefund`.
    function _sendOutbound(bytes32 key, Job storage j, uint256 value, address gasRefund) internal returns (uint256 back) {
        string memory chainId = j.chainId;
        address gasToken = UNIVERSAL_CORE.gasTokenPRC20ByChainNamespace(string.concat("eip155:", chainId));
        if (gasToken == address(0)) revert RemoteEvaluatorErrors.ChainNotSupported(chainId);
        bool pass = j.verdict == Verdict.PASS;
        uint256 rest = address(this).balance - value;
        UGPC.sendUniversalTxOutbound{value: value}(
            UniversalOutboundTxRequest({
                recipient: abi.encodePacked(gatewayOf[chainId]),
                token: gasToken,
                amount: 0,
                gasLimit: settleGasOf[chainId],
                gasPrice: 0,
                maxPCForGas: 0,
                payload: abi.encodeCall(IEvaluationGateway.settle, (j.kernel, j.jobId, j.captureKey, pass, j.reason)),
                revertRecipient: gasRefund
            })
        );
        back = address(this).balance - rest;
        emit VerdictSent(key, pass, value - back);
    }

    /// @dev Can still be answered: PENDING and below its expiry height. Past it the chain refuses votes, so the request
    ///      can only be expired, whether or not the sweeper has done so yet. The UniversalEvaluator's rule.
    function _inFlight(uint256 requestId) internal view returns (bool) {
        return READ_STATE.statusOf(requestId) == RequestStatus.PENDING
            && block.number < IReadStateViews(address(READ_STATE)).getPendingRead(requestId).expiryHeight;
    }

    function _spend(Job storage j, uint256 value) internal returns (uint256) {
        uint256 available = j.prepaid;
        if (available < value) revert RemoteEvaluatorErrors.PrepaidTooLow(value, available);
        j.prepaid = available - value;
        return value;
    }

    function _addPrepaid(bytes32 key, Job storage j) internal {
        if (msg.value == 0) return;
        j.prepaid += msg.value;
        emit Funded(key, msg.sender, msg.value);
    }

    function _pay(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert RemoteEvaluatorErrors.TransferFailed(to, amount);
    }

    function _setHeight(uint256[8] storage heights, uint256 read, uint64 h) internal {
        uint256 shift = 64 * (read % 4);
        heights[read / 4] = (heights[read / 4] & ~(uint256(type(uint64).max) << shift)) | (uint256(h) << shift);
    }

    function _height(uint256[8] storage heights, uint256 read) internal view returns (uint64) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(heights[read / 4] >> (64 * (read % 4))); // safe: masked to 64 bits by the cast
    }
}
