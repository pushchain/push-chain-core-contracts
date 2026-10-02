// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Session} from "./external/IAGW.sol";
import {SessionContext} from "../libraries/Types.sol";

/// @title IUniversalMarketplaceTerms
/// @notice The rules side of a card: validates its `RulesCardTerms` at registration, and checks the owner-signed
///         session against the card at `startJob`. EVM universal only. Reverts with `UniversalMarketplaceErrors`.
interface IUniversalMarketplaceTerms {
    // ═══ UMT_1: RULES TERMS ═══

    /// @notice Registration guards on a card's rules. Reverts `InvalidCard(reason)` on the first violation.
    /// @param rulesTerms `abi.encode(RulesCardTerms)`.
    /// @return asset The rules asset, for the marketplace's chain check.
    function validateRulesTerms(bytes calldata rulesTerms) external pure returns (address asset);

    /// @notice Rules ⊆ card: the session grants exactly the card's rules, to the card's agent, bound to this job.
    /// @param rulesTerms The card's stored `abi.encode(RulesCardTerms)`.
    /// @param s The owner-signed session.
    /// @param ctx The job's values.
    function verifySession(bytes calldata rulesTerms, Session calldata s, SessionContext calldata ctx) external pure;
}
