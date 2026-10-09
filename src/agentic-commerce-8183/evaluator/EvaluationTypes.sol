// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title EvaluationTypes — values and limits of the UniversalEvaluator
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

/// @notice The decode instructions for one read, kept so a callback never decodes the whole spec.
struct ReadPlan {
    bytes outputs;
    uint8[] field;
}

/// @notice How the evaluator sends Read State requests. Fixed at deployment.
/// @param readTtl                  Push blocks before an unanswered request may be expired. Must leave validators
///                                 time to wait for the read's confirmations.
/// @param callbackGasLimit         Gas an "after" read's callback declares; the last one applies the verdict.
///                                 At most Read State's 1,000,000.
/// @param snapshotCallbackGasLimit Gas a "before" (snapshot) read's callback declares; it only stores a value.
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
// Derived, not guessed: `JobSpecRules` refuses a return type whose fixed part (head) is longer than this,
//      so every valid shape fits, and only variable-length data (bytes, string, arrays) can push an answer over.
uint256 constant MAX_RESULT_LENGTH = 4096;
// Longest `Read.args`: up to 16 argument words.
uint256 constant MAX_ARGS_LENGTH = 512;
// Longest `Read.chainNamespace` and `Read.chainId`.
uint256 constant MAX_CHAIN_STRING_LENGTH = 32;
// Longest job `description` (the encoded `JobSpec`) the hook accepts at `fund`.
uint256 constant MAX_DESCRIPTION_LENGTH = 32_768;
