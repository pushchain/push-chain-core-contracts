// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title JobSpecTypes — the evaluation criteria of an ERC-8183 job
/// @notice One definition, shared by everything that writes or reads a job's criteria:
///         - UniversalMarketplace builds a `JobSpec` and stores `abi.encode(spec)` as the job's description;
///         - the UniversalHook decodes it at `fund` and freezes it;
///         - the UniversalEvaluator fires its reads and judges its checks and nodes.
/// @dev - Source: `docs-internal/Universal Evaluator V2 Design`, plus `origin` (marketplace PRD decision Z7).
///      - Field order is ABI. Never reorder, never insert; a change here changes every description.

/// @notice How a check compares. BOOL / CMP use the value now; NUM / PCT use the change since the snapshot.
enum EvalType {
    BOOL,
    CMP,
    NUM,
    PCT
}

/// @notice The comparison operator: == != > >= < <=.
enum Op {
    EQ,
    NEQ,
    GT,
    GTE,
    LT,
    LTE
}

/// @notice One step of the pass logic. CHECK: one check · ALL / ANY / AT_LEAST: combine children.
enum NodeKind {
    CHECK,
    ALL,
    ANY,
    AT_LEAST
}

/// @notice One contract call on one chain, and which value in its answer to use.
struct Read {
    string chainNamespace; // e.g. "eip155"
    string chainId; // e.g. "8453"
    uint16 minConfirmations; // confirmations this chain needs before the answer counts
    address target; // the contract to call
    bytes4 selector; // the view function
    bytes args; // abi-encoded arguments
    bytes outputs; // the function's return types, as T_* codes
    uint8[] field; // which returned value, by ABI position: [0] = 1st return value, [0, 2] = its 3rd field
}

/// @notice One comparison on one read.
struct Check {
    uint8 read; // index into reads
    EvalType evalType;
    Op op;
    int256 target; // in the contract's own units
}

/// @notice One step of the pass logic. Children always have a higher index than their parent.
struct Node {
    NodeKind kind;
    uint8 check; // CHECK only: index into checks
    uint8[] children; // ALL / ANY / AT_LEAST: indexes into nodes, each greater than this node's own
    uint8 k; // AT_LEAST only: how many children must pass
}

/// @notice A job's criteria. `nodes[0]` is the root: the job passes if it passes.
struct JobSpec {
    uint64 executeBy; // the provider must execute before this
    uint64 failFinalAt; // a FAIL only counts from a verify started after this
    Read[] reads;
    Check[] checks;
    Node[] nodes;
    bytes32 origin; // keccak256(abi.encode(marketplace, cardId, cardVersion, principal)); opaque to hook and evaluator
}

// ─────────────────────────────── return-type codes (`Read.outputs`) ───────────────────────────────

uint8 constant T_UINT = 1;
uint8 constant T_INT = 2;
uint8 constant T_BOOL = 3;
uint8 constant T_ADDRESS = 4;
uint8 constant T_BYTESN = 5;
uint8 constant T_BYTES = 6;
uint8 constant T_STRING = 7;
uint8 constant T_TUPLE = 8;
uint8 constant T_ARRAY = 9;
uint8 constant T_FIXED_ARRAY = 10;

// ─────────────────────────────── limits ───────────────────────────────

uint256 constant MAX_READS = 16;
uint256 constant MAX_CHECKS = 16;
uint256 constant MAX_NODES = 32;
