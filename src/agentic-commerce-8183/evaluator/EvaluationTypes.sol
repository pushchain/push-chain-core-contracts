// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {EvalType, Op} from "../libraries/JobSpecTypes.sol";

/// @title EvaluationTypes — values, limits and outside views of the UniversalEvaluator
/// @dev - Not part of the `JobSpec` wire format; changing these never changes a job's description.

/// @notice One decoded answer: whether the value could be read, and the number to compare.
struct Answer {
    bool ok;
    int256 value;
}

/// @notice An evaluation's result. NONE: not worked out yet. INCONCLUSIVE: a value the verdict depends on
///         could not be read.
enum Verdict {
    NONE,
    PASS,
    FAIL,
    INCONCLUSIVE
}

/// @notice Whether the client's wallet was used by its owner between `fund` and the verdict. Recorded only.
///         UNKNOWN: the wallet's counter could not be read.
enum OwnerCheck {
    UNKNOWN,
    CLEAN,
    TOUCHED
}

/// @notice A check as the evaluator keeps it: each side's reads as a bitmask (bit i: read i).
struct PackedCheck {
    uint32 left;
    uint32 right;
    EvalType evalType;
    Op op;
    int256 target;
}

/// @notice The decode instructions for one read, kept so a callback never decodes the whole spec.
struct ReadPlan {
    bytes outputs;
    uint8[] field;
}

/// @notice How the evaluator sends Read State requests. Fixed at deployment.
/// @param readTtl                  Push blocks before an unanswered request may be expired. Must leave validators
///                                 time to wait for the read's confirmations.
/// @param callbackGasLimit         Gas an evaluation read's callback declares; the one that decides the root
///                                 applies the verdict. At most Read State's 1,000,000.
/// @param snapshotCallbackGasLimit Gas a snapshot (PRE_EXECUTION) read's callback declares; it only stores a value.
/// @param budgetMultiplier         Callback budget = `gas limit × base fee × budgetMultiplier`, so a base fee that
///                                 rises before delivery still clears the node's check. Unspent budget is refunded.
/// @param maxHeightAge             Seconds a tracked height may be old when used, at `fund` and at `submit`. Non-zero.
/// @param maxConfirmations         Highest `Read.minConfirmations` a spec may ask for. Non-zero. Choose it so the
///                                 slowest supported chain reaches it well within `readTtl` and the job's expiry.
struct ReadConfig {
    uint64 readTtl;
    uint64 callbackGasLimit;
    uint64 snapshotCallbackGasLimit;
    uint256 budgetMultiplier;
    uint256 maxHeightAge;
    uint16 maxConfirmations;
}

// ─────────────────────────────── limits ───────────────────────────────

// Largest answer the hook and evaluator decode; a longer one is unreadable.
// Derived, not guessed: `JobSpecLib.validate` refuses a return type whose fixed part (head) is longer than this,
//      so every valid shape fits, and only variable-length data (bytes, string, arrays) can push an answer over.
uint256 constant MAX_RESULT_LENGTH = 4096;
// Longest `Read.args`: up to 16 argument words.
uint256 constant MAX_ARGS_LENGTH = 512;
// Longest `Read.chainNamespace` and `Read.chainId`.
uint256 constant MAX_CHAIN_STRING_LENGTH = 32;
// Longest job `description` (the encoded `JobSpec`) the hook accepts at `fund`.
uint256 constant MAX_DESCRIPTION_LENGTH = 32_768;

// ─────────────────────────────── outside views ───────────────────────────────

// The few views the evaluator reads on other teams' contracts that their own interfaces don't declare.

/// @title IAGWCheckpoints
/// @notice Mirror of the AGW's owner-side checkpoint counter.
/// @dev - Source: `push-agentic-wallets`, branch `pushAgenticWallet_v3` (`e704d5b`), `src/AGW.sol`
///        (`checkpointCount`, `lastCheckpointBlock`) and `docs/1_AGW.md` §4.5.
///      - Every owner-door call, rules grant and rules revoke advances the count, before the call runs; agent
///        actions never do. A job records the count at `fund`; a later count that differs means the owner side
///        touched the wallet during the job.
interface IAGWCheckpoints {
    function checkpointCount() external view returns (uint64);
}

/// @title IUniversalCoreHeights
/// @notice The two UniversalCore views the evaluator reads: Push's tracked height for a chain, and when it was last
///         updated.
/// @dev - Source: `src/UniversalCore.sol` (`chainHeightByChainNamespace`, `timestampObservedAtByChainNamespace`),
///        both written by `setChainMeta`. Keyed by the CAIP-2 string, e.g. `"eip155:8453"`.
///      - UniversalCore's own staleness setting guards gas data only, so callers check freshness themselves.
interface IUniversalCoreHeights {
    function chainHeightByChainNamespace(string memory chainNamespace) external view returns (uint256);

    function timestampObservedAtByChainNamespace(string memory chainNamespace) external view returns (uint256);
}

/// @title IReadStateDomains
/// @notice The one UniversalCallback view the evaluator reads that `IUniversalCallback` does not declare.
/// @dev Source: `src/UniversalCallback.sol` (`isDomainBlocked`), set by its admin with `updateBlockedDomain`. A blocked
///      domain makes `requestExternalReadSelf` revert `DomainBlocked`.
interface IReadStateDomains {
    function isDomainBlocked(string calldata chainNamespace, string calldata chainId) external view returns (bool);
}
