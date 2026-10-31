// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Session} from "./external/IAGW.sol";
import {SessionContext} from "../libraries/Types.sol";

/// @title IUniversalMarketplaceRules
/// @notice The rules side of an agent card: validates its `CardRule[]` (one rule per destination chain) at
///         registration, and checks the owner-signed sessions against the card at `openJob`. EVM universal only.
///         Reverts with `UniversalMarketplaceErrors`.
interface IUniversalMarketplaceRules {
    // ═══ UMR_1: RULES ═══

    /// @notice Registration guards on a card's rules. Reverts on the first violation.
    /// @dev - Rules: 1..`maxRules`; each an EVM CAIP-2 chain no other rule names; `validUntil` / `expectedCEA` blank.
    ///      - Per rule (R1-R4, R8-R17): asset count, no zero or duplicate token; allowed-call count, pin counts,
    ///        `MARKER_WALLET` under EQ only, no identical entries, no pinless entry beside a pinned one; ERC-20
    ///        approve pinned and capped, transfer / transferFrom to the user's wallet, no increaseAllowance.
    ///      - Across rules (R5-R7): exactly one asset's `maxTotal` is `MARKER_PRINCIPAL`, with a non-zero per-call cap;
    ///        no other asset carries the marker.
    /// @param rules `abi.encode(CardRule[])`.
    /// @param maxRules The marketplace's live cap (`maxRulesPerCard`).
    /// @return chainHashes Each rule's `keccak256(chainNamespace)`, in rule order.
    /// @return tokens Every asset's token, rule by rule.
    /// @return tokenChains The chain hash of the rule each token sits in, for the marketplace's asset-chain check.
    function validateAgentCardRules(bytes calldata rules, uint256 maxRules)
        external
        pure
        returns (bytes32[] memory chainHashes, address[] memory tokens, bytes32[] memory tokenChains);

    /// @notice Rules = card (C1-C14), per card rule: session `i` grants exactly rule `i`, markers filled for this
    ///         job, to the card's agent, bound to this job and to the AGW's CEA on that rule's chain. Reverts on
    ///         the first mismatch, naming the rule.
    /// @dev - Count: one session per card rule, same order.
    ///      - Shape: agent, one action, one policy, envelope version, chain.
    ///      - Terms: assets and caps, gas cap, allowed calls and pins, expiry, expected CEA.
    /// @param cardRules The card's stored `abi.encode(CardRule[])`.
    /// @param sessions The owner-signed sessions.
    /// @param ctx The job's values; `ctx.expectedCEAs[i]` is the AGW's CEA on rule `i`'s chain.
    function checkRulesMatchCard(bytes calldata cardRules, Session[] calldata sessions, SessionContext calldata ctx)
        external
        pure;
}
