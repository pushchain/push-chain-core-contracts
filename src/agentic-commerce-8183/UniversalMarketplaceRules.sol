// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    AssetCap,
    AllowedCall,
    ArgPin,
    PinOp,
    UniversalTerms,
    ENVELOPE_VERSION,
    MAX_ASSETS,
    MAX_PINS,
    MAX_ALLOWED_CALL_PINS
} from "@push-agw/libraries/Types.sol";
import {UniversalMarketplaceErrors} from "./libraries/Errors.sol";
import {CardRule, SessionContext, MARKER_WALLET, MARKER_PRINCIPAL} from "./libraries/Types.sol";
import {IUniversalMarketplaceRules} from "./interfaces/IUniversalMarketplaceRules.sol";
import {Session} from "./interfaces/external/IAGW.sol";

/// @title UniversalMarketplaceRules
/// @notice The rules side of an agent card: registration guards on its `CardRule[]` (one rule per destination
///         chain), and rules = card at `openJob` (one signed session per card rule).
/// @dev - EVM universal only. Pure logic, no storage, no admin; split out of the marketplace for EIP-170.
///      - Reverts with `UniversalMarketplaceErrors`: a revert here bubbles through the marketplace unchanged.
///      - Not upgradeable. A rule change is a new deployment plus a marketplace upgrade that points at it.
///      - Known limit: whether a `MARKER_PRINCIPAL` pin sits on the PRINCIPAL token's `approve` is not checked.
///        `IPRC20` has no source-token view, so a PRC20 cannot be mapped to its destination token. The verified tag
///        covers it.
contract UniversalMarketplaceRules is IUniversalMarketplaceRules {
    /// @dev URP's allow-list bound (internal there, so mirrored): a card that could never be granted is refused.
    uint256 internal constant MAX_ALLOWED_CALLS = 32;

    bytes4 internal constant ERC20_TRANSFER = IERC20.transfer.selector;
    bytes4 internal constant ERC20_APPROVE = IERC20.approve.selector;
    bytes4 internal constant ERC20_TRANSFER_FROM = IERC20.transferFrom.selector;
    /// @dev Not on OZ 5's IERC20.
    bytes4 internal constant ERC20_INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));

    bytes7 internal constant EVM_PREFIX = "eip155:";

    /// @dev Calldata offsets of an ERC-20 call's first and second argument words.
    uint16 internal constant ARG0 = 4;
    uint16 internal constant ARG1 = 36;

    // ═════════════════════════════════ rules = card ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplaceRules
    /// @dev - One session per card rule, same order; each pair runs C1-C14 and every error names the pair.
    ///      - The session never carries a marker: C8 and C12 compare against the filled-in value.
    ///      - Never compared: the session's validator, policy address, action target and selector, userOp and
    ///        ERC-7739 lists, paymaster flag and salt. The AGW pins every one of those itself at `grantRules`
    ///        (v6 `_grantRules`), and overwrites the salt with its grant nonce.
    function checkRulesMatchCard(bytes calldata cardRules, Session[] calldata sessions, SessionContext calldata ctx)
        external
        pure
    {
        CardRule[] memory rules = abi.decode(cardRules, (CardRule[]));
        uint256 n = rules.length;
        if (sessions.length != n) revert UniversalMarketplaceErrors.SessionCountMismatch(n, sessions.length);
        // The marketplace builds one CEA per rule; a mismatch is a bug there, not a caller error.
        assert(ctx.expectedCEAs.length == n);
        for (uint256 i; i < n; ++i) {
            _checkRule(rules[i], sessions[i], ctx, i);
        }
    }

    /// @dev C1-C14 for card rule `i` and its session.
    function _checkRule(CardRule memory c, Session calldata session, SessionContext calldata ctx, uint256 i)
        internal
        pure
    {
        if (keccak256(session.sessionValidatorInitData) != keccak256(abi.encode(ctx.agent))) {
            revert UniversalMarketplaceErrors.AgentMismatch(i);
        }
        if (session.actions.length != 1) revert UniversalMarketplaceErrors.ActionCount(i);
        if (session.actions[0].actionPolicies.length != 1) revert UniversalMarketplaceErrors.PolicyShape(i);

        UniversalTerms memory t = _decodeEnvelope(
            session.actions[0].actionPolicies[0].initData, keccak256(bytes(c.chainNamespace)), i
        );
        _matchAssets(c.terms.assets, t.assets, ctx.principal, i);
        if (t.maxGasPerCall != c.terms.maxGasPerCall) revert UniversalMarketplaceErrors.GasCapMismatch(i);
        address cea = ctx.expectedCEAs[i];
        _matchCalls(c.terms.allowedCalls, t.allowedCalls, cea, ctx.principal, i);
        if (t.validUntil != ctx.expiredAt) revert UniversalMarketplaceErrors.ExpiryMismatch(i);
        if (t.expectedCEA != cea) revert UniversalMarketplaceErrors.ExpectedCEAMismatch(i, cea, t.expectedCEA);
    }

    /// @dev C4-C5. The version is read from the first word BEFORE any decode, as URP does, so a pre-v6
    ///      two-field envelope (first word 64, its string offset) is named instead of panicking the decoder.
    function _decodeEnvelope(bytes calldata d, bytes32 chainHash, uint256 i)
        internal
        pure
        returns (UniversalTerms memory)
    {
        uint256 version = d.length < 32 ? 0 : uint256(bytes32(d[:32]));
        if (version != ENVELOPE_VERSION) revert UniversalMarketplaceErrors.EnvelopeVersionMismatch(i, version);
        (, string memory chainNamespace, bytes memory body) = abi.decode(d, (uint16, string, bytes));
        if (keccak256(bytes(chainNamespace)) != chainHash) revert UniversalMarketplaceErrors.ChainMismatch(i);
        return abi.decode(body, (UniversalTerms));
    }

    /// @dev C6-C9: same tokens in the same order; the principal asset's caps filled with the principal (D3); every
    ///      other asset's caps copied exactly.
    function _matchAssets(AssetCap[] memory card, AssetCap[] memory signed, uint256 principal, uint256 rule)
        internal
        pure
    {
        uint256 n = card.length;
        if (signed.length != n) revert UniversalMarketplaceErrors.AssetCountMismatch(rule, n, signed.length);
        for (uint256 j; j < n; ++j) {
            if (signed[j].token != card[j].token) revert UniversalMarketplaceErrors.AssetMismatch(rule, j);
        }
        for (uint256 j; j < n; ++j) {
            AssetCap memory a = card[j];
            uint256 total = a.maxTotal;
            uint256 perCall = a.maxPerCall;
            if (total == uint256(MARKER_PRINCIPAL)) {
                total = principal;
                if (perCall == uint256(MARKER_PRINCIPAL)) perCall = principal;
            }
            if (signed[j].maxTotal != total || signed[j].maxPerCall != perCall) {
                revert UniversalMarketplaceErrors.AssetMismatch(rule, j);
            }
        }
    }

    /// @dev C11-C12, one loop: every field of every call equal, every pin's offset and op equal, then its value
    ///      equal with markers filled in (`MARKER_WALLET` = this rule's CEA).
    function _matchCalls(
        AllowedCall[] memory card,
        AllowedCall[] memory signed,
        address cea,
        uint256 principalAmount,
        uint256 rule
    ) internal pure {
        if (signed.length != card.length) revert UniversalMarketplaceErrors.ActionsMismatch(rule);
        bytes32 wallet = bytes32(uint256(uint160(cea)));
        bytes32 principal = bytes32(principalAmount);
        for (uint256 k; k < card.length; ++k) {
            AllowedCall memory a = card[k];
            AllowedCall memory b = signed[k];
            if (
                a.target != b.target || a.selector != b.selector || a.beneficiaryOffset != b.beneficiaryOffset
                    || a.hasBeneficiary != b.hasBeneficiary || a.maxValue != b.maxValue || a.pins.length != b.pins.length
            ) revert UniversalMarketplaceErrors.ActionsMismatch(rule);
            for (uint256 m; m < a.pins.length; ++m) {
                ArgPin memory p = a.pins[m];
                ArgPin memory q = b.pins[m];
                if (p.offset != q.offset || p.op != q.op) revert UniversalMarketplaceErrors.ActionsMismatch(rule);
                bytes32 want = p.value == MARKER_WALLET ? wallet : p.value == MARKER_PRINCIPAL ? principal : p.value;
                if (q.value != want) revert UniversalMarketplaceErrors.PinMismatch(rule, k, m);
            }
        }
    }

    // ═════════════════════════════════ registration guards ═════════════════════════════════

    /// @inheritdoc IUniversalMarketplaceRules
    /// @dev Order: count · per rule (chain namespace, duplicate chain, blank per-job fields, R1-R17) · the principal
    ///      across all rules. The first failure reverts. Malformed bytes revert in the decoder, without data.
    function validateAgentCardRules(bytes calldata rules, uint256 maxRules)
        external
        pure
        returns (bytes32[] memory chainHashes, address[] memory tokens, bytes32[] memory tokenChains)
    {
        CardRule[] memory rs = abi.decode(rules, (CardRule[]));
        uint256 n = rs.length;
        if (n == 0) revert UniversalMarketplaceErrors.RulesEmpty();
        if (n > maxRules) revert UniversalMarketplaceErrors.TooManyRules(n, maxRules);

        chainHashes = new bytes32[](n);
        uint256 nTokens;
        for (uint256 i; i < n; ++i) {
            chainHashes[i] = _validateRuleChain(rs[i], chainHashes, i);
            UniversalTerms memory t = rs[i].terms;
            if (t.validUntil != 0 || t.expectedCEA != address(0)) revert UniversalMarketplaceErrors.RuleHasAgent(i);
            _validateAssets(t.assets);
            _validateCallShape(t.allowedCalls);
            _validateDuplicates(t.allowedCalls);
            _validateErc20(t.allowedCalls, i);
            nTokens += t.assets.length;
        }
        _validatePrincipal(rs);

        tokens = new address[](nTokens);
        tokenChains = new bytes32[](nTokens);
        uint256 k;
        for (uint256 i; i < n; ++i) {
            AssetCap[] memory assets = rs[i].terms.assets;
            for (uint256 j; j < assets.length; ++j) {
                tokens[k] = assets[j].token;
                tokenChains[k] = chainHashes[i];
                ++k;
            }
        }
    }

    /// @dev An EVM CAIP-2 namespace no earlier rule names. Returns its hash.
    function _validateRuleChain(CardRule memory r, bytes32[] memory seen, uint256 i) internal pure returns (bytes32 h) {
        bytes memory ns = bytes(r.chainNamespace);
        if (ns.length <= EVM_PREFIX.length || bytes7(ns) != EVM_PREFIX) {
            revert UniversalMarketplaceErrors.InvalidAgentCard("chain namespace");
        }
        h = keccak256(ns);
        for (uint256 j; j < i; ++j) {
            if (seen[j] == h) revert UniversalMarketplaceErrors.DuplicateChain(i);
        }
    }

    /// @dev R1-R4, per rule: 1..MAX_ASSETS assets, no zero token, no token twice.
    function _validateAssets(AssetCap[] memory assets) internal pure {
        uint256 n = assets.length;
        if (n == 0 || n > MAX_ASSETS) revert UniversalMarketplaceErrors.InvalidAgentCard("asset count");
        for (uint256 i; i < n; ++i) {
            if (assets[i].token == address(0)) revert UniversalMarketplaceErrors.InvalidAgentCard("asset zero");
        }
        for (uint256 i; i < n; ++i) {
            for (uint256 j; j < i; ++j) {
                if (assets[j].token == assets[i].token) {
                    revert UniversalMarketplaceErrors.InvalidAgentCard("duplicate asset");
                }
            }
        }
    }

    /// @dev R5-R7, across all rules: exactly one asset has `maxTotal == MARKER_PRINCIPAL` (the principal); its
    ///      per-call cap is non-zero; no other asset carries the marker in either cap.
    function _validatePrincipal(CardRule[] memory rs) internal pure {
        uint256 count;
        for (uint256 i; i < rs.length; ++i) {
            AssetCap[] memory assets = rs[i].terms.assets;
            for (uint256 j; j < assets.length; ++j) {
                if (assets[j].maxTotal == uint256(MARKER_PRINCIPAL)) {
                    ++count;
                    if (assets[j].maxPerCall == 0) {
                        revert UniversalMarketplaceErrors.InvalidAgentCard("principal per-call zero");
                    }
                } else if (assets[j].maxPerCall == uint256(MARKER_PRINCIPAL)) {
                    revert UniversalMarketplaceErrors.InvalidAgentCard("marker off principal asset");
                }
            }
        }
        if (count == 0) revert UniversalMarketplaceErrors.NoPrincipal();
        if (count > 1) revert UniversalMarketplaceErrors.ManyPrincipals();
    }

    /// @dev R8-R10: 1-32 calls; at most MAX_PINS pins per call and MAX_ALLOWED_CALL_PINS in all; `MARKER_WALLET`
    ///      only under EQ (a ceiling of an address is meaningless).
    function _validateCallShape(AllowedCall[] memory calls) internal pure {
        uint256 n = calls.length;
        if (n == 0 || n > MAX_ALLOWED_CALLS) revert UniversalMarketplaceErrors.InvalidAgentCard("allow-list size");
        uint256 total;
        for (uint256 i; i < n; ++i) {
            uint256 pins = calls[i].pins.length;
            total += pins;
            if (pins > MAX_PINS || total > MAX_ALLOWED_CALL_PINS) {
                revert UniversalMarketplaceErrors.InvalidAgentCard("too many pins");
            }
        }
        for (uint256 i; i < n; ++i) {
            ArgPin[] memory pins = calls[i].pins;
            for (uint256 k; k < pins.length; ++k) {
                if (pins[k].value == MARKER_WALLET && pins[k].op != PinOp.EQ) {
                    revert UniversalMarketplaceErrors.InvalidAgentCard("wallet marker op");
                }
            }
        }
    }

    /// @dev R11-R12. Several entries may share a (target, selector) — "approve to Aave or to Uniswap" — but only
    ///      if each is pinned: a call passes if ANY entry passes, so a pinless one beside a pinned one makes the
    ///      pins pointless (AGW v6 `AllowedCall` docs; URP allows it, the SDK and this helper refuse it).
    function _validateDuplicates(AllowedCall[] memory calls) internal pure {
        uint256 n = calls.length;
        bytes32[] memory hashes = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            hashes[i] = keccak256(abi.encode(calls[i]));
            for (uint256 j; j < i; ++j) {
                if (hashes[j] == hashes[i]) revert UniversalMarketplaceErrors.InvalidAgentCard("duplicate call");
            }
        }
        for (uint256 i; i < n; ++i) {
            for (uint256 j; j < i; ++j) {
                if (
                    calls[j].target == calls[i].target && calls[j].selector == calls[i].selector
                        && (calls[j].pins.length == 0 || calls[i].pins.length == 0)
                ) revert UniversalMarketplaceErrors.InvalidAgentCard("unpinned duplicate");
            }
        }
    }

    /// @dev R13-R17 for rule `rule`, each over every call before the next (D1: the agent approves, but only under
    ///      pins).
    ///      - approve: spender pinned EQ to a clean, non-zero address word (which excludes both markers: their
    ///        high 96 bits are non-zero), and amount capped by a MAX pin (a literal or `MARKER_PRINCIPAL`).
    ///      - transfer / transferFrom: recipient bound to the user's account, by the beneficiary field or by an EQ
    ///        `MARKER_WALLET` pin.
    function _validateErc20(AllowedCall[] memory calls, uint256 rule) internal pure {
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].selector == ERC20_INCREASE_ALLOWANCE) {
                revert UniversalMarketplaceErrors.InvalidAgentCard("increaseAllowance");
            }
        }
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].selector == ERC20_APPROVE && !_hasSpenderPin(calls[i].pins)) {
                revert UniversalMarketplaceErrors.UnpinnedApprove(rule, i);
            }
        }
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].selector == ERC20_APPROVE && !_hasPin(calls[i].pins, ARG1, PinOp.MAX)) {
                revert UniversalMarketplaceErrors.InvalidAgentCard("approve amount not capped");
            }
        }
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].selector == ERC20_TRANSFER && !_recipientIsWallet(calls[i], ARG0)) {
                revert UniversalMarketplaceErrors.UnpinnedTransfer(rule, i);
            }
        }
        for (uint256 i; i < calls.length; ++i) {
            if (calls[i].selector == ERC20_TRANSFER_FROM && !_recipientIsWallet(calls[i], ARG1)) {
                revert UniversalMarketplaceErrors.UnpinnedTransfer(rule, i);
            }
        }
    }

    /// @dev Some pin is `{4, EQ, v}` with `v` a non-zero address word.
    function _hasSpenderPin(ArgPin[] memory pins) internal pure returns (bool) {
        for (uint256 k; k < pins.length; ++k) {
            ArgPin memory p = pins[k];
            if (p.offset == ARG0 && p.op == PinOp.EQ && p.value != 0 && uint256(p.value) >> 160 == 0) return true;
        }
        return false;
    }

    /// @dev Some pin is `{offset, op, *}`.
    function _hasPin(ArgPin[] memory pins, uint16 offset, PinOp op) internal pure returns (bool) {
        for (uint256 k; k < pins.length; ++k) {
            if (pins[k].offset == offset && pins[k].op == op) return true;
        }
        return false;
    }

    /// @dev The recipient word at `offset` is the user's account: the beneficiary field, or `{offset, EQ, MARKER_WALLET}`.
    function _recipientIsWallet(AllowedCall memory call, uint16 offset) internal pure returns (bool) {
        if (call.hasBeneficiary && call.beneficiaryOffset == offset) return true;
        for (uint256 k; k < call.pins.length; ++k) {
            ArgPin memory p = call.pins[k];
            if (p.offset == offset && p.op == PinOp.EQ && p.value == MARKER_WALLET) return true;
        }
        return false;
    }
}
