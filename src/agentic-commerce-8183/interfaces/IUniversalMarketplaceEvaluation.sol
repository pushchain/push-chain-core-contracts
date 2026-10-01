// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {EvalType, Op, Node} from "../libraries/JobSpecTypes.sol";

// ─────────────────────────────── the card's evaluation template ───────────────────────────────
//
// A card's "how done is judged": the V2 JobSpec with holes. The card fixes everything that is the same for
// every job; `build` fills in the per-job values (the AGW's CEA, the principal, the user's params, the times).

/// @notice Where a fill's 32-byte word comes from. CEA = the AGW's CEA on the READ's chain.
enum FillSource {
    CEA,
    PARAM
}

/// @notice Overwrites `args[32·word : 32·word + 32]` per job. `param` is used by PARAM only (0 otherwise).
struct Fill {
    uint8 word;
    FillSource source;
    uint8 param;
}

/// @notice A `Read` with fills. Copied into the JobSpec verbatim, then filled.
struct ReadTemplate {
    string chainNamespace; // "eip155" only (v1)
    string chainId; // decimal digits; never Push itself (v1)
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
///         PARAM a param index · CEA 0 (the CEA of the check's read chain).
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

/// @notice The whole template. `nodes` is copied into the JobSpec verbatim.
struct EvaluationTemplate {
    ReadTemplate[] reads;
    CheckTemplate[] checks;
    Node[] nodes;
    ParamBounds[] params;
}

/// @notice The per-job values `build` fills in.
struct BuildContext {
    address market; // answers expectedCEAOf
    address agw;
    uint256 principal;
    uint48 executeBy;
    uint32 settleWindow;
    int256[] params;
    bytes32 origin;
}

/// @title IEvaluationMarket — the marketplace views the evaluation contract reads.
interface IEvaluationMarket {
    /// @notice keccak256("eip155:" ‖ decimal(chain id)) of Push itself, which no read may name.
    function pushChainHash() external view returns (bytes32);

    /// @notice A destination chain's CEA factory and proxy implementation; zero if the chain has none.
    function ceaDeployment(bytes32 chainHash) external view returns (address ceaFactory, address ceaProxyImpl);

    /// @notice The AGW's CEA on `chainHash`. Reverts for a chain without a CEA deployment.
    function expectedCEAOf(address agw, bytes32 chainHash) external view returns (address);
}

/// @title IUniversalMarketplaceEvaluation
/// @notice The evaluation side of a card: validates a card's `EvaluationTemplate` at registration, and builds a
///         job's `JobSpec` from it at `startJob`. Reverts with IUniversalMarketplaceErrors.
interface IUniversalMarketplaceEvaluation {
    /// @notice Structure, types and logic of a template. Reverts `InvalidCard("eval: …")` on the first violation.
    /// @param evaluation `abi.encode(EvaluationTemplate)`.
    /// @param market The marketplace whose chain configuration the template is checked against.
    function validateTemplate(bytes calldata evaluation, address market) external view;

    /// @notice The job's criteria: `abi.encode(JobSpec)`, the `createJob` description.
    /// @dev    Assumes `validateTemplate` passed; never re-validates the template's structure.
    /// @param evaluation A validated template.
    /// @param ctx The per-job values.
    /// @return description `abi.encode(JobSpec)`.
    function build(bytes calldata evaluation, BuildContext calldata ctx)
        external
        view
        returns (bytes memory description);
}
