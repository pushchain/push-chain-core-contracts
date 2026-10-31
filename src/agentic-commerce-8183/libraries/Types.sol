// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {OwnerIntent, UniversalTerms} from "@push-agw/libraries/Types.sol";
import {Session} from "../interfaces/external/IAGW.sol";
import {Evaluation, Operation, Logic, ReadAt} from "./JobSpecTypes.sol";

/// @title Types — the UniversalMarketplace package's structs, enums and markers, file-level.
/// @dev - Cards, jobs and init: the marketplace (UniversalMarketplace, IUniversalMarketplace).
///      - `CardRule`, `SessionContext`, the markers: the rules helper (UniversalMarketplaceRules).
///      - The criteria template: JobSpecBuilder. The built criteria (`JobSpec`) stay in JobSpecTypes.sol, the wire
///        format shared with the UniversalHook and the UniversalEvaluator.
///      - AGW types (`UniversalTerms`, `OwnerIntent`, ...) are imported from AGW v6, never copied.

// ─────────────────────────────── markers (D2, D3) ───────────────────────────────
//
// Published constants: the SDK uses the same values. A card holds a marker; the signed session holds the value the
// marketplace fills in for this job. Both have non-zero high 96 bits, so neither is a clean address word.

/// @dev In a card: "the user's account (CEA) on this rule's chain". EQ pins only.
///      keccak256("push.marketplace.marker.WALLET").
bytes32 constant MARKER_WALLET = 0x38beb8621ef19c2ac125b45b1ac07225511365301161eb56ac7a21aa8641cf5a;
/// @dev In a card: "this job's principal". Pins (EQ or MAX) and the principal asset's caps (as uint256).
///      keccak256("push.marketplace.marker.PRINCIPAL").
bytes32 constant MARKER_PRINCIPAL = 0xc12ba2e9bfe16dd303c04d7f517245a6b49fd69f9d0e5c82d14be8c18ef34d52;

/// @dev Hard cap on rules per card. The live cap is the admin setting `maxRulesPerCard` (≤ this).
uint8 constant MAX_RULES = 4;

// ─────────────────────────────── cards, jobs, init ───────────────────────────────

/// @notice One standing offer from one provider. One card per provider. Chains live in its rules.
/// @dev `provider` and `active` are contract-written; caller values are ignored.
struct AgentCard {
    address provider; // msg.sender at registration · the rules agent · 8183 provider · fee recipient
    bytes32 jobType; // e.g. keccak256("LENDING_DEPOSIT")
    string metadataURI; // off-chain JSON: name, summary, ABIs, criteria in words, param units
    bytes32 metadataHash; // keccak256 of that JSON
    uint256 providerFee; // reference price in paymentToken; the client funds against it (not enforced on-chain)
    address paymentToken; // until the kernel's K-12, must equal KERNEL.paymentToken()
    uint32 minDuration; // job length bounds, seconds; expiredAt − openJob time must sit inside
    uint32 maxDuration;
    bool active;
}

/// @notice What the agent may do on one destination chain: the AGW v6 rule with the per-job fields blank.
/// @dev - `terms.validUntil` and `terms.expectedCEA` are 0 in the card; `openJob` requires the signed session to
///        carry the job's `expiredAt` and the wallet's CEA on `chainNamespace`.
///      - `terms.assets` caps and `terms.allowedCalls` pins may hold the markers. Exactly one asset across all of a
///        card's rules is the principal: its `maxTotal` is `MARKER_PRINCIPAL`.
struct CardRule {
    string chainNamespace; // full CAIP-2, "eip155:<id>", never Push
    UniversalTerms terms; // AGW v6: validUntil, expectedCEA, assets, maxGasPerCall, allowedCalls
}

/// @notice A destination chain's CEA factory and proxy implementation, for `computeCEA`.
struct CEADeployment {
    address ceaFactory;
    address ceaProxyImpl;
}

/// @notice The full card, for the SDK. One call.
struct AgentCardView {
    AgentCard card;
    bytes rules; // abi.encode(CardRule[])
    bytes jobSpecTemplate; // abi.encode(JobSpecTemplate)
    uint256 version;
    bool verified;
    bool disabled;
}

/// @notice Per-job inputs the owner signs (inside the createJob calldata and the sessions).
struct JobInputs {
    uint256 principal; // > 0
    uint48 expiredAt; // signed; the SDK derives it from the user's duration
    int256[] params; // one per template param, within its bounds
}

/// @notice Everything `openJob` needs.
struct OpenJobParams {
    uint256 cardId;
    uint256 cardVersion; // the version the owner signed against
    JobInputs job;
    Session[] sessions; // one per card rule, same order
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
    address rules; // UniversalMarketplaceRules
    address admin; // receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE
}

// ─────────────────────────────── rules check (UniversalMarketplaceRules) ───────────────────────────────

/// @notice The per-job values `checkRulesMatchCard` checks the sessions against.
struct SessionContext {
    address agent; // card.provider
    uint256 principal;
    uint48 expiredAt;
    address[] expectedCEAs; // one per card rule, same order: the AGW's CEA on that rule's chain
}

// ─────────────────────────────── a card's criteria template ───────────────────────────────
//
// The JobSpec with holes. The card fixes everything that is the same for every job; `JobSpecBuilder.build`
// fills in the per-job values (the AGW's CEA, the principal, the user's params).

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
    // a CardRule's chainNamespace is the full CAIP-2 string
    string chainNamespace;
    string chainId; // e.g. "1"
    uint16 minConfirmations;
    address target;
    bytes4 selector;
    bytes args;
    Fill[] fills;
    bytes outputs;
    uint8[] field;
    ReadAt at; // copied verbatim into Read.at
}

/// @notice Where a check's target comes from.
enum TargetSource {
    FIXED,
    PRINCIPAL_BPS,
    PARAM,
    CEA
}

/// @notice A `Check` whose target is a source. `left` / `right` are copied verbatim (indexes into reads).
///         `value`: FIXED the target · PRINCIPAL_BPS bps of principal · PARAM a param index ·
///         CEA unused (the CEA on the chain of `left[0]`'s read).
struct CheckTemplate {
    uint8[] left;
    uint8[] right;
    Evaluation evaluation;
    Operation operation;
    TargetSource source;
    int256 value;
}

/// @notice Inclusive bounds on one per-job number the user supplies.
struct ParamBounds {
    int256 min;
    int256 max;
}

/// @notice The whole template, stored on the card as `abi.encode(JobSpecTemplate)`. `logic` is copied verbatim;
///         the builder always writes `allowedMutability = NONE`.
struct JobSpecTemplate {
    ReadTemplate[] reads;
    CheckTemplate[] checks;
    Logic[] logic;
    ParamBounds[] params;
}

/// @notice The per-job values `build` fills in.
struct BuildContext {
    address agw;
    uint256 principal;
    int256[] params;
    bytes32 origin;
}
