// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalMarketplace, IUniversalMarketplaceErrors} from "./interfaces/IUniversalMarketplace.sol";
import {IUniversalMarketplaceTerms, SessionContext} from "./interfaces/IUniversalMarketplaceTerms.sol";
import {Session, AllowedCall, UniversalTerms} from "./interfaces/external/IAGW.sol";

/// @title UniversalMarketplaceTerms
/// @notice The rules side of an agent card: registration guards on its `RulesCardTerms`, and rules ⊆ card at
///         `startJob`. EVM universal only. Pure logic, no storage, no admin.
/// @dev - Split out of the marketplace for EIP-170. Pure, so each use costs one STATICCALL and no behaviour.
///      - Reverts with IUniversalMarketplaceErrors: a revert here bubbles through the marketplace unchanged.
///      - Not upgradeable. A rule change is a new deployment plus a marketplace upgrade that points at it.
contract UniversalMarketplaceTerms is IUniversalMarketplaceTerms, IUniversalMarketplaceErrors {
    /// @dev URP's allow-list bound, mirrored so a card that could never be granted is never registered.
    uint256 internal constant MAX_ALLOWED_CALLS = 32;
    uint256 internal constant MAX_APPROVALS = 8;

    bytes4 internal constant ERC20_TRANSFER = 0xa9059cbb;
    bytes4 internal constant ERC20_APPROVE = 0x095ea7b3;
    bytes4 internal constant ERC20_TRANSFER_FROM = 0x23b872dd;
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = 0x39509351;

    // ───────── rules ⊆ card ─────────

    /// @inheritdoc IUniversalMarketplaceTerms
    /// @dev - Order: agent, shape, chain, then each term.
    ///      - `approvals` are not compared: they are the owner's actions, never agent authority.
    function verifySession(bytes calldata rulesTerms, Session calldata s, SessionContext calldata ctx)
        external
        pure
    {
        if (keccak256(s.sessionValidatorInitData) != keccak256(abi.encode(ctx.agent))) revert AgentMismatch();
        if (s.actions.length != 1) revert ActionCount();
        if (s.actions[0].actionPolicies.length != 1) revert PolicyShape(0);
        (string memory chain, bytes memory body) =
            abi.decode(s.actions[0].actionPolicies[0].initData, (string, bytes));
        if (keccak256(bytes(chain)) != ctx.chainHash) revert ChainMismatch(0);

        UniversalTerms memory t = abi.decode(body, (UniversalTerms));
        IUniversalMarketplace.RulesCardTerms memory u = abi.decode(rulesTerms, (IUniversalMarketplace.RulesCardTerms));
        if (t.asset != u.asset) revert AssetMismatch();
        if (t.maxPCPerCall != u.maxPCPerCall) revert PCCapMismatch();
        if (keccak256(abi.encode(t.allowedCalls)) != keccak256(abi.encode(u.allowedCalls))) revert ActionsMismatch();
        if (t.maxAmountTotal != ctx.principal || t.maxAmountPerCall > ctx.principal) revert CapMismatch();
        if (t.validUntil != ctx.expiredAt) revert ExpiryMismatch();
        if (t.expectedCEA != ctx.expectedCEA) revert ExpectedCEAMismatch(ctx.expectedCEA, t.expectedCEA);
    }

    // ───────── registration guards ─────────

    /// @inheritdoc IUniversalMarketplaceTerms
    function validateRulesTerms(bytes calldata rulesTerms) external pure returns (address asset) {
        IUniversalMarketplace.RulesCardTerms memory u = abi.decode(rulesTerms, (IUniversalMarketplace.RulesCardTerms));
        if (u.asset == address(0)) revert InvalidCard("asset zero");
        _validateAllowedCalls(u.allowedCalls);
        _validateApprovals(u.approvals);
        return u.asset;
    }

    /// @dev 1-32 calls, no duplicate (target, selector), no approval, and ERC-20 recipients pinned to the CEA.
    function _validateAllowedCalls(AllowedCall[] memory calls) internal pure {
        uint256 n = calls.length;
        if (n == 0 || n > MAX_ALLOWED_CALLS) revert InvalidCard("allow-list size");
        for (uint256 i; i < n; ++i) {
            AllowedCall memory call = calls[i];
            for (uint256 j; j < i; ++j) {
                if (calls[j].target == call.target && calls[j].selector == call.selector) {
                    revert InvalidCard("duplicate call");
                }
            }
            // A rule can only pin the beneficiary to the AGW's CEA, which is meaningless for a spender:
            // approvals are the owner's (Approval[]), never agent authority.
            if (call.selector == ERC20_APPROVE || call.selector == ERC20_INCREASE_ALLOWANCE) {
                revert InvalidCard("erc20 approval");
            }
            if (call.selector == ERC20_TRANSFER && !(call.hasBeneficiary && call.beneficiaryOffset == 4)) {
                revert InvalidCard("erc20 transfer recipient");
            }
            if (call.selector == ERC20_TRANSFER_FROM && !(call.hasBeneficiary && call.beneficiaryOffset == 36)) {
                revert InvalidCard("erc20 transferFrom recipient");
            }
        }
    }

    /// @dev At most 8; each names a token and a spender, has a cap matching its kind, and no pair repeats.
    function _validateApprovals(IUniversalMarketplace.Approval[] memory approvals) internal pure {
        if (approvals.length > MAX_APPROVALS) revert InvalidCard("approval count");
        for (uint256 i; i < approvals.length; ++i) {
            IUniversalMarketplace.Approval memory a = approvals[i];
            if (a.token == address(0)) revert InvalidCard("approval token");
            if (a.spender == address(0)) revert InvalidCard("approval spender");
            if (a.capIsPrincipal ? a.cap != 0 : a.cap == 0) revert InvalidCard("approval cap");
            for (uint256 j; j < i; ++j) {
                if (approvals[j].token == a.token && approvals[j].spender == a.spender) {
                    revert InvalidCard("duplicate approval");
                }
            }
        }
    }
}
