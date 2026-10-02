// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AllowedCall, OwnerIntent, Session} from "../interfaces/external/IAGW.sol";
import {EvalType, Op, Node} from "./JobSpecTypes.sol";

/// @title Types — the UniversalMarketplace package's structs and enums, file-level.
/// @dev - Cards, jobs and init: the marketplace (UniversalMarketplace, IUniversalMarketplace).
///      - `SessionContext`: the Terms helper.
///      - The criteria template: JobSpecBuilder. The built criteria (`JobSpec`) stay in JobSpecTypes.sol, the wire
///        format shared with the UniversalHook and the UniversalEvaluator.

// ─────────────────────────────── cards, jobs, init ───────────────────────────────

/// @notice One standing offer from one provider: one job type on one EVM execution chain.
/// @dev - `provider` and `active` are contract-written; caller values are ignored.
///      - `chainNamespace` is immutable after registration.
struct AgentCard {
    address provider; // msg.sender at registration · the rules agent · 8183 provider · fee recipient
    bytes32 jobType; // e.g. keccak256("LENDING_DEPOSIT")
    string metadataURI; // off-chain JSON: name, summary, ABIs, criteria in words, param units
    bytes32 metadataHash; // keccak256 of that JSON
    string chainNamespace; // CAIP-2 execution chain, "eip155:<id>", never Push
    uint256 fee; // reference price in the kernel's payment token; enforced at 8183 fund
    uint256 principalMin; // the job's size, in the rules asset's units
    uint256 principalMax;
    uint32 minDuration; // job expiry window, seconds from startJob
    uint32 maxDuration;
    uint32 minExecuteWindow; // executeBy ≥ startJob time + this
    uint32 settleWindow; // failFinalAt = executeBy + this; executeBy + this ≤ expiredAt
    bool active;
}

/// @notice A token allowance the agent needs on the execution chain.
/// @dev Executed by the OWNER in the funding transaction the SDK builds; never agent authority.
struct Approval {
    address token; // on the execution chain
    address spender;
    bool capIsPrincipal; // true: amount = principal (cap must be 0) · false: amount = cap (> 0)
    uint256 cap;
}

/// @notice What the agent needs. `expectedCEA`, `validUntil` and the amount caps are per job.
struct RulesCardTerms {
    address asset; // PRC20 whose SOURCE_CHAIN_NAMESPACE() == card.chainNamespace
    uint256 maxPCPerCall;
    AllowedCall[] allowedCalls;
    Approval[] approvals;
}

/// @notice A destination chain's CEA factory and proxy implementation, for `expectedCEAOf`.
struct CEADeployment {
    address ceaFactory;
    address ceaProxyImpl;
}

/// @notice The full card, for the SDK. One call.
struct CardView {
    AgentCard card;
    bytes rulesTerms; // abi.encode(RulesCardTerms)
    bytes evaluation; // abi.encode(EvaluationTemplate)
    uint256 version;
    bool verified;
    bool adminDisabled;
}

/// @notice Per-job inputs the owner signs (inside the createJob calldata and the session).
struct JobInputs {
    uint256 principal;
    uint48 expiredAt;
    uint48 executeBy;
    int256[] params; // one per template param, within its bounds
}

/// @notice Everything `startJob` needs.
struct StartJobParams {
    uint256 cardId;
    uint256 cardVersion; // the version the owner signed against
    JobInputs job;
    Session session;
    OwnerIntent intent;
    bytes sig;
    string label; // wallet label, used only when deploying
}

/// @notice What `previewIntent` needs to build the OwnerIntent the owner signs.
struct IntentRequest {
    uint256 cardId;
    address owner;
    uint96 index;
    JobInputs job;
    uint48 deadline;
    uint256 signerChainId;
}

/// @notice `initialize` arguments. Every field must be non-zero.
struct InitParams {
    address agwFactory;
    address kernel;
    address hook; // must be whitelisted on the kernel
    address evaluator; // the marketplace-wide 8183 evaluator
    address terms; // UniversalMarketplaceTerms
    address admin; // receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE
}

// ─────────────────────────────── rules check (Terms) ───────────────────────────────

/// @notice The per-job values `verifySession` checks the session against.
struct SessionContext {
    address agent; // card.provider
    bytes32 chainHash; // keccak256(bytes(card.chainNamespace))
    uint256 principal;
    uint48 expiredAt;
    address expectedCEA; // the AGW's CEA on the card's chain, derived by the marketplace
}

// ─────────────────────────────── a card's criteria template ───────────────────────────────
//
// The V2 JobSpec with holes. The card fixes everything that is the same for every job; `JobSpecBuilder.build`
// fills in the per-job values (the AGW's CEA, the principal, the user's params, the times).

/// @notice Where a fill's 32-byte word comes from. CEA = the AGW's CEA on the READ's chain.
enum FillSource {
    CEA,
    PARAM
}

/// @notice Overwrites `args[32·word : 32·word + 32]` per job. `param` is used by PARAM only.
struct Fill {
    uint8 word;
    FillSource source;
    uint8 param;
}

/// @notice A `Read` with fills. Copied into the JobSpec, then filled.
struct ReadTemplate {
    // namespace only ("eip155"), with chainId separate — the Read State split (AGW doc D6);
    // AgentCard.chainNamespace is the full CAIP-2 string
    string chainNamespace;
    string chainId; // e.g. "1"
    uint16 minConfirmations;
    address target;
    bytes4 selector;
    bytes args;
    Fill[] fills;
    bytes outputs;
    uint8[] field;
}

/// @notice Where a check's target comes from.
enum TargetSource {
    FIXED,
    PRINCIPAL_BPS,
    PARAM,
    CEA
}

/// @notice A `Check` whose target is a source. `value`: FIXED the target · PRINCIPAL_BPS bps of principal ·
///         PARAM a param index · CEA unused (the CEA of the check's read chain).
struct CheckTemplate {
    uint8 read;
    EvalType evalType;
    Op op;
    TargetSource source;
    int256 value;
}

/// @notice Inclusive bounds on one per-job number the user supplies.
struct ParamBounds {
    int256 min;
    int256 max;
}

/// @notice The whole template, stored on the card as `abi.encode(EvaluationTemplate)`. `nodes` is copied verbatim.
struct EvaluationTemplate {
    ReadTemplate[] reads;
    CheckTemplate[] checks;
    Node[] nodes;
    ParamBounds[] params;
}

/// @notice The per-job values `build` fills in.
struct BuildContext {
    address agw;
    uint256 principal;
    uint48 executeBy;
    uint32 settleWindow;
    int256[] params;
    bytes32 origin;
}
