// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UniversalMarketplaceErrors} from "./libraries/Errors.sol";
import {Approval, RulesCardTerms, SessionContext} from "./libraries/Types.sol";
import {IUniversalMarketplaceTerms} from "./interfaces/IUniversalMarketplaceTerms.sol";
import {Session, AllowedCall, UniversalTerms} from "./interfaces/external/IAGW.sol";

/// @title UniversalMarketplaceTerms
/// @notice The rules side of an agent card: registration guards on its `RulesCardTerms`, and rules ⊆ card at
///         `startJob`. EVM universal only. Pure logic, no storage, no admin.
/// @dev - Split out of the marketplace for EIP-170. Pure, so each use costs one STATICCALL and no behaviour.
///      - Reverts with `UniversalMarketplaceErrors`: a revert here bubbles through the marketplace unchanged.
///      - Not upgradeable. A rule change is a new deployment plus a marketplace upgrade that points at it.
contract UniversalMarketplaceTerms is IUniversalMarketplaceTerms {
    /// @dev URP's allow-list bound, mirrored so a card that could never be granted is never registered.
    uint256 internal constant MAX_ALLOWED_CALLS = 32;
    uint256 internal constant MAX_APPROVALS = 8;

    bytes4 internal constant ERC20_TRANSFER = IERC20.transfer.selector;
    bytes4 internal constant ERC20_APPROVE = IERC20.approve.selector;
    bytes4 internal constant ERC20_TRANSFER_FROM = IERC20.transferFrom.selector;
    /// @dev Not on OZ 5's IERC20.
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));

    // ───────── rules ⊆ card ─────────

    /// @inheritdoc IUniversalMarketplaceTerms
    /// @dev - Order: agent, shape, chain, then each term.
    ///      - `approvals` are not compared: they are the owner's actions, never agent authority.
    function verifySession(bytes calldata rulesTerms, Session calldata s, SessionContext calldata ctx) external pure {
        if (keccak256(s.sessionValidatorInitData) != keccak256(abi.encode(ctx.agent))) {
            revert UniversalMarketplaceErrors.AgentMismatch();
        }
        if (s.actions.length != 1) revert UniversalMarketplaceErrors.ActionCount();
        if (s.actions[0].actionPolicies.length != 1) revert UniversalMarketplaceErrors.PolicyShape(0);
        (string memory chainNamespace, bytes memory body) =
            abi.decode(s.actions[0].actionPolicies[0].initData, (string, bytes));
        if (keccak256(bytes(chainNamespace)) != ctx.chainHash) revert UniversalMarketplaceErrors.ChainMismatch(0);

        UniversalTerms memory t = abi.decode(body, (UniversalTerms));
        RulesCardTerms memory u = abi.decode(rulesTerms, (RulesCardTerms));
        if (t.asset != u.asset) revert UniversalMarketplaceErrors.AssetMismatch();
        if (t.maxPCPerCall != u.maxPCPerCall) revert UniversalMarketplaceErrors.PCCapMismatch();
        if (keccak256(abi.encode(t.allowedCalls)) != keccak256(abi.encode(u.allowedCalls))) {
            revert UniversalMarketplaceErrors.ActionsMismatch();
        }
        if (t.maxAmountTotal != ctx.principal || t.maxAmountPerCall > ctx.principal) {
            revert UniversalMarketplaceErrors.CapMismatch();
        }
        if (t.validUntil != ctx.expiredAt) revert UniversalMarketplaceErrors.ExpiryMismatch();
        if (t.expectedCEA != ctx.expectedCEA) {
            revert UniversalMarketplaceErrors.ExpectedCEAMismatch(ctx.expectedCEA, t.expectedCEA);
        }
    }

    // ───────── registration guards ─────────

    /// @inheritdoc IUniversalMarketplaceTerms
    function validateRulesTerms(bytes calldata rulesTerms) external pure returns (address asset) {
        RulesCardTerms memory u = abi.decode(rulesTerms, (RulesCardTerms));
        if (u.asset == address(0)) revert UniversalMarketplaceErrors.InvalidCard("asset zero");
        _validateAllowedCalls(u.allowedCalls);
        _validateApprovals(u.approvals);
        return u.asset;
    }

    /// @dev 1-32 calls, no duplicate (target, selector), no approval, and ERC-20 recipients pinned to the CEA.
    function _validateAllowedCalls(AllowedCall[] memory calls) internal pure {
        uint256 n = calls.length;
        if (n == 0 || n > MAX_ALLOWED_CALLS) revert UniversalMarketplaceErrors.InvalidCard("allow-list size");
        for (uint256 i; i < n; ++i) {
            AllowedCall memory call = calls[i];
            for (uint256 j; j < i; ++j) {
                if (calls[j].target == call.target && calls[j].selector == call.selector) {
                    revert UniversalMarketplaceErrors.InvalidCard("duplicate call");
                }
            }
            // A rule can only pin the beneficiary to the AGW's CEA, which is meaningless for a spender:
            // approvals are the owner's (Approval[]), never agent authority.
            if (call.selector == ERC20_APPROVE || call.selector == ERC20_INCREASE_ALLOWANCE) {
                revert UniversalMarketplaceErrors.InvalidCard("erc20 approval");
            }
            if (call.selector == ERC20_TRANSFER && !(call.hasBeneficiary && call.beneficiaryOffset == 4)) {
                revert UniversalMarketplaceErrors.InvalidCard("erc20 transfer recipient");
            }
            if (call.selector == ERC20_TRANSFER_FROM && !(call.hasBeneficiary && call.beneficiaryOffset == 36)) {
                revert UniversalMarketplaceErrors.InvalidCard("erc20 transferFrom recipient");
            }
        }
    }

    /// @dev At most 8; each names a token and a spender, has a cap matching its kind, and no pair repeats.
    function _validateApprovals(Approval[] memory approvals) internal pure {
        if (approvals.length > MAX_APPROVALS) revert UniversalMarketplaceErrors.InvalidCard("approval count");
        for (uint256 i; i < approvals.length; ++i) {
            Approval memory a = approvals[i];
            if (a.token == address(0)) revert UniversalMarketplaceErrors.InvalidCard("approval token");
            if (a.spender == address(0)) revert UniversalMarketplaceErrors.InvalidCard("approval spender");
            if (a.capIsPrincipal ? a.cap != 0 : a.cap == 0) {
                revert UniversalMarketplaceErrors.InvalidCard("approval cap");
            }
            for (uint256 j; j < i; ++j) {
                if (approvals[j].token == a.token && approvals[j].spender == a.spender) {
                    revert UniversalMarketplaceErrors.InvalidCard("duplicate approval");
                }
            }
        }
    }
}
