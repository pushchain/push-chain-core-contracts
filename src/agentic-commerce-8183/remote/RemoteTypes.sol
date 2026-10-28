// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title RemoteTypes — what the EvaluationGateway (on a remote chain) and the RemoteEvaluator (on Push) share
/// @notice Phase 2: a job on an ERC-8183 kernel on another EVM chain names the EvaluationGateway as its evaluator, and
///         Push judges it with the Phase 1 criteria (`JobSpec`).
/// @dev - The kernel views here are the two `Job` layouts deployed today, read from their verified sources:
///        layout V: Virtuals `AgenticCommerceV3` (Base, Base Sepolia, BSC testnet) and Push's own `AgenticCommerce`;
///        layout R: the ERC-8183 reference order, as APEX `AgenticCommerceUpgradeable` (BSC) returns it, with its two
///        extra fields. The status enum is the same everywhere (Open, Funded, Submitted, Completed, Rejected, Expired).
///      - The Push-side views are the deployed `UniversalGatewayPC` (8-field request, selector 0x77b86bec) and the
///        remote Vault's `CEAFactory()` getter.

import {IUniversalCoreHeights} from "../evaluator/EvaluationTypes.sol";

// ─────────────────────────────── shared values ───────────────────────────────

/// @notice What a gateway call pays for on Push. The caller quotes it on Push before sending.
/// @param pcForJob     PC the payload hands to the job on Push (the UniversalPayload `value`). It must not exceed what
///                     the inbound's gas swaps into, after the payload's own Push gas.
/// @param gasLimit     Push gas for the payload.
/// @param maxFeePerGas At least Push's base fee; the node charges the base fee only.
struct PushFees {
    uint256 pcForJob;
    uint256 gasLimit;
    uint256 maxFeePerGas;
}

/// @notice A job as the gateway reads it from any supported kernel.
struct RemoteJob {
    address client;
    address provider;
    address evaluator;
    address hook;
    uint8 status;
    uint64 expiredAt;
    string description;
}

// Kernel `Job` layouts the gateway can read. 0 means the kernel is not supported.
uint8 constant LAYOUT_V = 1;
uint8 constant LAYOUT_R = 2;

// ERC-8183 job statuses the gateway acts on.
uint8 constant JOB_FUNDED = 1;
uint8 constant JOB_SUBMITTED = 2;

// The gateway's two inbounds for one job, each sent through its own InboundSender: the snapshot and the verify.
uint32 constant SNAPSHOT_SLOT = 0;
uint32 constant VERIFY_SLOT = 1;

// A verdict as it travels to the remote chain and is recorded there.
uint8 constant VERDICT_NONE = 0;
uint8 constant VERDICT_PASS = 1;
uint8 constant VERDICT_FAIL = 2;

/// @notice Keys shared by both sides. Push takes `chainId` from the gateway's UEA origin; the gateway uses its own
///         `block.chainid` as a decimal string.
///         - `snapshotKey`: one job's criteria and PRE answers, taken at S. Push files the job under it.
///         - `captureKey`: that snapshot plus E and the values the gateway read inside `verify` (`POST_AT_VERIFY`).
///           The verdict carries it, and the gateway applies a verdict only for its own record.
///         - `senderOf`: the InboundSender a gateway sends one job message through (CREATE2 from the gateway), whose
///           UEA on Push is the message's caller.
library RemoteKeys {
    function senderSalt(address kernel, uint256 jobId, uint32 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(kernel, jobId, slot));
    }

    /// @param senderCodeHash keccak256 of the InboundSender creation code the gateway deploys.
    function senderOf(address gateway, address kernel, uint256 jobId, uint32 slot, bytes32 senderCodeHash)
        internal
        pure
        returns (address)
    {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), gateway, senderSalt(kernel, jobId, slot), senderCodeHash)
        );
        // forge-lint: disable-next-line(unsafe-typecast)
        return address(uint160(uint256(h))); // the CREATE2 address: the low 20 bytes
    }

    function snapshotKey(
        string memory chainId,
        address kernel,
        uint256 jobId,
        bytes32 specHash,
        bytes32 preHash,
        uint64 snapshotBlock
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(chainId, kernel, jobId, specHash, preHash, snapshotBlock));
    }

    /// @param verifyHash keccak256(abi.encode(verifyResults)); zero before `verify`.
    function captureKey(bytes32 snapshotKey_, uint64 verifyBlock, bytes32 verifyHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(snapshotKey_, verifyBlock, verifyHash));
    }
}

// ─────────────────────────────── kernels (remote chain) ───────────────────────────────

/// @notice Layout V: Virtuals `AgenticCommerceV3` and Push's `AgenticCommerce`.
interface IKernelLayoutV {
    struct JobV {
        address client;
        uint8 status;
        address provider;
        uint48 expiredAt;
        address evaluator;
        address hook;
        uint256 budget;
        string description;
    }

    function getJob(uint256 jobId) external view returns (JobV memory);
}

/// @notice Layout R: the ERC-8183 reference order, followed by APEX's `submittedAt` and `deliverable`.
interface IKernelLayoutR {
    struct JobR {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        string description;
        uint256 budget;
        uint256 expiredAt;
        uint8 status;
        address hook;
        uint256 submittedAt;
        bytes32 deliverable;
    }

    function getJob(uint256 jobId) external view returns (JobR memory);
}

/// @notice The two kernel calls the gateway makes as a job's evaluator. Same signature on every supported kernel.
interface IKernelVerdict {
    function complete(uint256 jobId, bytes32 reason, bytes calldata optParams) external;

    function reject(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
}

/// @notice The two getters the gateway follows to find the factory that deploys CEAs on its chain.
interface IUniversalGatewayVault {
    function VAULT() external view returns (address);
}

interface IVaultCEAFactory {
    function CEAFactory() external view returns (address);
}

// ─────────────────────────────── Push ───────────────────────────────

/// @notice Mirror of `UniversalOutboundTxRequest` in push-chain-gateway-contracts (`TypesUGPC.sol`).
struct UniversalOutboundTxRequest {
    bytes recipient; // EVM: the 20-byte packed address
    address token; // the destination's gas PRC20 for a payload-only outbound; never zero
    uint256 amount;
    uint256 gasLimit; // at least the chain's base gas limit
    uint256 gasPrice; // 0: the chain's current price
    uint256 maxPCForGas; // 0: use all of msg.value after the protocol fee
    bytes payload;
    address revertRecipient;
}

/// @notice The deployed `UniversalGatewayPC` entry point. The PC surplus is refunded to `msg.sender` in the same call.
interface IUniversalGatewayPC {
    function sendUniversalTxOutbound(UniversalOutboundTxRequest calldata req) external payable;
}

/// @notice The UniversalCore views the RemoteEvaluator reads.
interface IRemoteCore is IUniversalCoreHeights {
    function gasTokenPRC20ByChainNamespace(string memory chainNamespace) external view returns (address);
}

/// @notice The UniversalCallback getter that names the module account executing every callback.
interface IReadStateModule {
    function UNIVERSAL_CALLBACK_MODULE() external view returns (address);
}

// ─────────────────────────────── the two contracts, as each other sees them ───────────────────────────────

/// @notice What the gateway's senders' UEAs call on Push. Push files each job under its snapshot key.
interface IRemoteEvaluator {
    /// @notice The job's two inbounds: the snapshot (`verifyBlock == 0`, `verifyResults` empty) and the verify.
    /// @param payer         Who paid this inbound on the remote chain (the gateway's caller). Unspent PC, callback
    ///                      budgets and outbound gas go to its UEA on Push.
    /// @param preResults    One entry per read: the answer the gateway read at S for a PRE read on its chain; empty
    ///                      for every other read.
    /// @param verifyResults One entry per read: the answer the gateway read inside `verify` for a `POST_AT_VERIFY`
    ///                      read; empty for every other read.
    function onRemoteJob(
        address kernel,
        uint256 jobId,
        address payer,
        bytes calldata spec,
        bytes[] calldata preResults,
        uint64 snapshotBlock,
        uint64 verifyBlock,
        bytes[] calldata verifyResults
    ) external payable;

    function sendReads(bytes32 key, bytes calldata spec) external payable;

    /// @param results One entry per read: its answer's raw bytes, as Read State delivered it or as `verify` read it;
    ///                anything for a PRE read on the gateway's chain or a read with no answer yet.
    function sendVerdict(bytes32 key, bytes calldata spec, bytes[] calldata preResults, bytes[] calldata results)
        external
        payable;
}

/// @notice What the RemoteEvaluator's CEA calls on the remote chain.
interface IEvaluationGateway {
    function settle(address kernel, uint256 jobId, bytes32 captureKey, bool pass, bytes32 reason) external;
}

// ─────────────────────────────── errors ───────────────────────────────

library EvaluationGatewayErrors {
    error ZeroValue();
    error LayoutsMismatch();
    error BadLayout(address kernel, uint8 layout);
    error UnsupportedKernel(address kernel);
    error UnknownJob(address kernel, uint256 jobId);
    error NotOurJob(address kernel, uint256 jobId);
    error HookNotAllowed(address hook);
    error WrongStatus(address kernel, uint256 jobId, uint8 status);
    error NotClient(address caller);
    error NotProvider(address caller);
    error AlreadySnapshotted(address kernel, uint256 jobId);
    error NoSnapshot(address kernel, uint256 jobId);
    error AlreadyVerified(address kernel, uint256 jobId);
    error NotVerified(address kernel, uint256 jobId);
    error SameBlockAsSnapshot();
    error TooCloseToExpiry(uint256 expiredAt, uint256 latestStart);
    error SpecMismatch();
    error PreResultsMismatch();
    error VerifyResultsMismatch();
    error ReadNotHere(uint256 read);
    error NoInboundNeeded();
    error BadSlot(uint32 slot);
    error NoGasSent();
    error BadPushFees();
    error ReadGasTooLow(uint256 gasLeft, uint256 needed);
    error NotEvaluatorCEA(address caller);
    error NothingToApply(address kernel, uint256 jobId);
    error VerdictAlreadyRecorded(address kernel, uint256 jobId);
    error SpecIsValid(address kernel, uint256 jobId);
    error CheckRanOutOfGas();
    error TransferFailed(address to, uint256 amount);
}

library RemoteEvaluatorErrors {
    error ZeroValue();
    error DuplicateChain(string chainId);
    error NotGateway(address caller);
    error CallerIsNotReadState(address caller);
    error CallerIsNotSelf(address caller);
    error InsideCallback();
    error ResultsLength(uint256 got, uint256 want);
    error SuppliedWrongRead(uint256 read);
    error ReadNotOnGatewayChain(uint256 read);
    error SnapshotNotRegistered(bytes32 key);
    error HeightNotAfterSnapshot(uint256 read, uint64 atSnapshot, uint64 tracked);
    error BadBlocks(uint64 snapshotBlock, uint64 verifyBlock);
    error UnknownJob(bytes32 key);
    error SpecMismatch(bytes32 key);
    error PreResultsMismatch(bytes32 key);
    error ResultMismatch(uint256 read);
    error AwaitingVerify(bytes32 key);
    error NotDecided(bytes32 key);
    error NothingToSend(bytes32 key);
    error NoVerdict(bytes32 key);
    error ResendUnpaid(bytes32 key);
    error PrepaidTooLow(uint256 needed, uint256 available);
    error ChainNotSupported(string chainId);
    error NotClaimable(bytes32 key);
    error TransferFailed(address to, uint256 amount);
}
