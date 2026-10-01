// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IAGW — byte-exact mirrors of the Push Agentic Wallet (AGW) types and functions the marketplace needs.
/// @dev - Source: the AGW after its naming change (`push-agentic-wallet`, branch `nomenclature-changes`,
///        `docs-internal/sdk-first-changes/N-nomenclature_prd.md` §2.3 and Appendix B):
///        `src/libraries/Types.sol` (OwnerIntent, OWNER_LANE_FLAG),
///        `src/interfaces/IUniversalRulesPolicy.sol` (the UNIVERSAL terms),
///        `lib/smartsessions/contracts/DataTypes.sol` (Session and its parts),
///        `src/AGW.sol` (the owner-intent doors and two views).
///      - `rulesId` is the AGW's name for the engine's `permissionId`; the two are the same value.
///      - Agent identity (AGW D3, `D3-agent-identity-sender-validator_prd.md` §4.1): a session's
///        `sessionValidatorInitData` is `abi.encode(address agent)`, exactly 32 bytes.
///      - UNIVERSAL rules only: the NATIVE rulebook's types are not mirrored (native cards are out of v1).
///      - MIRRORS, NOT IMPORTS: the AGW repo compiles `cancun` against OZ 5.7 and its engine types pull
///        five vendor remappings this repo does not have. Field order and types are what matter — the
///        ABI encoding and every selector derive from them. The AGW repo's E2E suite pins each mirror
///        against the real type (`test_E2E_12`).
///      - `Session.sessionValidator` is `ISessionValidator` upstream; a contract type is `address` in
///        the ABI, so `address` here encodes and selects identically.

// ─────────────────────────────── owner intent ───────────────────────────────

/// @dev Mirror of the AGW `OwnerIntent`. Every field, in order.
struct OwnerIntent {
    address owner;
    address wallet;
    address executor;
    uint96 index;
    bytes32 sessionHash;
    bytes32 mode;
    bytes32 execCalldataHash;
    uint192 nonceKey;
    uint64 nonceSeq;
    uint64 grantNonce;
    uint48 deadline;
    uint256 signerChainId;
}

/// @dev Mirror of the AGW `OWNER_LANE_FLAG` — the top bit of a uint192 nonce key.
uint192 constant OWNER_LANE_FLAG = uint192(1) << 191;

// ─────────────────────────────── SmartSession ───────────────────────────────

struct PolicyData {
    address policy;
    bytes initData;
}

struct ActionData {
    bytes4 actionTargetSelector;
    address actionTarget;
    PolicyData[] actionPolicies;
}

struct ERC7739Context {
    bytes32 appDomainSeparator;
    string[] contentNames;
}

struct ERC7739Data {
    ERC7739Context[] allowedERC7739Content;
    PolicyData[] erc1271Policies;
}

struct Session {
    address sessionValidator;
    bytes sessionValidatorInitData;
    bytes32 salt;
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    ActionData[] actions;
    bool permitERC4337Paymaster;
}

// ─────────────────────────────── rules wire types (UniversalRulesPolicy) ───────────────────────────────

/// @dev Mirror of `IUniversalRulesPolicy.AllowedCall`.
struct AllowedCall {
    address target;
    bytes4 selector;
    uint16 beneficiaryOffset;
    bool hasBeneficiary;
    uint256 maxValue;
}

/// @dev Mirror of `IUniversalRulesPolicy.UniversalTerms` — a UNIVERSAL envelope's body.
struct UniversalTerms {
    uint48 validUntil;
    address expectedCEA;
    address asset;
    uint256 maxAmountPerCall;
    uint256 maxAmountTotal;
    uint256 maxPCPerCall;
    AllowedCall[] allowedCalls;
}

// ─────────────────────────────── the wallet ───────────────────────────────

/// @title IAGW — the wallet functions the marketplace calls.
interface IAGW {
    /// @notice `grantRules`, authorised by the owner's signed OwnerIntent.
    function grantRulesWithSig(Session calldata session, OwnerIntent calldata intent, bytes calldata sig)
        external
        returns (bytes32 rulesId);

    /// @notice The owner door, authorised by the owner's signed OwnerIntent.
    function executeWithSig(
        bytes32 mode,
        bytes calldata executionCalldata,
        OwnerIntent calldata intent,
        bytes calldata sig
    ) external;

    /// @notice Next expected sequence number in a replay lane.
    function getNonce(uint192 nonceKey) external view returns (uint64);

    /// @notice The grant nonce the next grant will consume.
    function grantNonce() external view returns (uint64);
}
