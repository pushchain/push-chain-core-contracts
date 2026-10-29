// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {AssetCap, AllowedCall, ArgPin, PinOp, UniversalTerms} from "@push-agw/libraries/Types.sol";
import {UniversalMarketplaceRules} from "../../src/agentic-commerce-8183/UniversalMarketplaceRules.sol";
import {UniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {Session, ActionData, PolicyData} from "../../src/agentic-commerce-8183/interfaces/external/IAGW.sol";
import {
    CardRule,
    SessionContext,
    MARKER_WALLET,
    MARKER_PRINCIPAL,
    MAX_RULES
} from "../../src/agentic-commerce-8183/libraries/Types.sol";
import {RulesFixtures, SessionSkeleton} from "./helpers/RulesFixtures.sol";

/// @title UniversalMarketplaceRules — unit suite. Direct calls; the marketplace suite covers the same rules through
///        `registerAgentCard` and `openJob`. Single-rule cases run on one Sepolia rule (index 0); the multi-rule cases
///        (MT12-MT16) cover the per-card checks and the per-pair error index.
contract UniversalMarketplaceRulesTest is Test, RulesFixtures {
    UniversalMarketplaceRules internal rules;

    address internal agent = makeAddr("agent");
    address internal usdcPrc20 = makeAddr("pUSDC.sepolia");
    address internal pethPrc20 = makeAddr("pETH.sepolia");
    address internal pool = makeAddr("pool");
    address internal usdc = makeAddr("USDC");
    address internal cea = makeAddr("cea");
    uint256 internal constant PRINCIPAL = 500e6;
    uint48 internal constant EXPIRY = 1_800_000_000;

    function setUp() public {
        rules = new UniversalMarketplaceRules();
    }

    // ───────── builders ─────────

    function _rules() internal view returns (CardRule memory) {
        return _cardRules(usdcPrc20, usdc, pool);
    }

    function _rules2() internal view returns (CardRule memory) {
        return _cardRulesTwoAssets(usdcPrc20, usdc, pool, pethPrc20);
    }

    /// @dev A Base rule that does not carry the principal.
    function _baseRule() internal returns (CardRule memory) {
        return _sideRule(BASE, makeAddr("pETH.base"), makeAddr("pool.base"));
    }

    function _enc(CardRule memory r) internal pure returns (bytes memory) {
        return abi.encode(_rulesOf(r));
    }

    function _validate(CardRule memory r) internal view returns (address[] memory tokens) {
        (, tokens,) = rules.validateAgentCardRules(_enc(r), MAX_RULES);
    }

    function _skeleton() internal returns (SessionSkeleton memory) {
        return SessionSkeleton({
            validator: makeAddr("validator"),
            actionTarget: makeAddr("gateway"),
            actionSelector: bytes4(0x12345678),
            policy: makeAddr("urp")
        });
    }

    function _terms(CardRule memory r) internal view returns (UniversalTerms memory) {
        return _fillTerms(r, PRINCIPAL, EXPIRY, cea);
    }

    function _session(bytes memory initData) internal returns (Session memory) {
        return _wrapSession(initData, agent, _skeleton());
    }

    function _sessionFor(UniversalTerms memory t) internal returns (Session memory) {
        return _session(_envelope(t, SEPOLIA));
    }

    function _sessions(Session memory a) internal pure returns (Session[] memory ss) {
        ss = new Session[](1);
        ss[0] = a;
    }

    function _sessions(Session memory a, Session memory b) internal pure returns (Session[] memory ss) {
        ss = new Session[](2);
        (ss[0], ss[1]) = (a, b);
    }

    function _ctx() internal view returns (SessionContext memory c) {
        c.agent = agent;
        c.principal = PRINCIPAL;
        c.expiredAt = EXPIRY;
        c.expectedCEAs = new address[](1);
        c.expectedCEAs[0] = cea;
    }

    function _expectInvalid(CardRule memory r, string memory reason) internal {
        bytes memory enc = _enc(r);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.InvalidAgentCard.selector, reason));
        rules.validateAgentCardRules(enc, MAX_RULES);
    }

    function _expectRule(CardRule memory r, bytes memory err) internal {
        bytes memory enc = _enc(r);
        vm.expectRevert(err);
        rules.validateAgentCardRules(enc, MAX_RULES);
    }

    function _withCalls(AllowedCall[] memory calls) internal view returns (CardRule memory r) {
        r = _rules();
        r.terms.allowedCalls = calls;
    }

    function _calls1(AllowedCall memory c) internal pure returns (AllowedCall[] memory calls) {
        calls = new AllowedCall[](1);
        calls[0] = c;
    }

    function _calls2(AllowedCall memory a, AllowedCall memory b) internal pure returns (AllowedCall[] memory calls) {
        calls = new AllowedCall[](2);
        (calls[0], calls[1]) = (a, b);
    }

    function _pins2(ArgPin memory a, ArgPin memory b) internal pure returns (ArgPin[] memory pins) {
        pins = new ArgPin[](2);
        (pins[0], pins[1]) = (a, b);
    }

    function _noPins() internal pure returns (ArgPin[] memory) {
        return new ArgPin[](0);
    }

    function _approveTo(address spender, PinOp amountOp, bytes32 amount) internal view returns (AllowedCall memory) {
        return _allowed(usdc, APPROVE, 0, false, _pins2(_pin(4, PinOp.EQ, _word(spender)), _pin(36, amountOp, amount)));
    }

    /// @dev `n` distinct, pinless supply calls (distinct targets).
    function _manyCalls(uint256 n) internal pure returns (AllowedCall[] memory calls) {
        calls = new AllowedCall[](n);
        for (uint256 i; i < n; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            calls[i] = _allowed(address(uint160(0x1000 + i)), SUPPLY, 0, false, new ArgPin[](0)); // i < 64
        }
    }

    function _distinctPins(uint256 n) internal pure returns (ArgPin[] memory pins) {
        pins = new ArgPin[](n);
        for (uint256 k; k < n; ++k) {
            // forge-lint: disable-next-line(unsafe-typecast)
            pins[k] = _pin(uint16(4 + 32 * k), PinOp.EQ, bytes32(k + 1)); // k < 9
        }
    }

    // ═════════════════════════════ validateAgentCardRules ═════════════════════════════

    function test_MT01_validate_returnsTokens() public view {
        address[] memory one = _validate(_rules());
        assertEq(one.length, 1);
        assertEq(one[0], usdcPrc20);
        address[] memory two = _validate(_rules2());
        assertEq(two.length, 2);
        assertEq(two[0], usdcPrc20);
        assertEq(two[1], pethPrc20);
    }

    function test_MT02_assetChecks() public {
        CardRule memory r = _rules();
        r.terms.assets = new AssetCap[](0);
        _expectInvalid(r, "asset count"); // R1: zero
        r = _rules();
        AssetCap[] memory nine = new AssetCap[](9);
        nine[0] = r.terms.assets[0];
        for (uint256 i = 1; i < 9; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            nine[i] = AssetCap({token: address(uint160(0x2000 + i)), maxPerCall: 0, maxTotal: 0}); // i < 9
        }
        r.terms.assets = nine;
        _expectInvalid(r, "asset count"); // R1: MAX_ASSETS + 1

        r = _rules2();
        r.terms.assets[1].token = address(0);
        _expectInvalid(r, "asset zero"); // R3

        r = _rules2();
        r.terms.assets[1].token = usdcPrc20;
        _expectInvalid(r, "duplicate asset"); // R4

        // boundary: MAX_ASSETS (8) passes
        r = _rules();
        AssetCap[] memory eight = new AssetCap[](8);
        for (uint256 i; i < 8; ++i) {
            eight[i] = nine[i];
        }
        r.terms.assets = eight;
        assertEq(_validate((r)).length, 8);
    }

    function test_MT03_principalMarkers() public {
        CardRule memory r = _rules();
        r.terms.assets[0].maxTotal = 1000e6; // a fixed total, but the per-call cap still holds the marker
        _expectInvalid(r, "marker off principal asset");
        r.terms.assets[0].maxPerCall = 1000e6;
        _expectRule(r, abi.encodeWithSelector(UniversalMarketplaceErrors.NoPrincipal.selector)); // R5: no principal

        r = _rules();
        r.terms.assets[0].maxPerCall = 0;
        _expectInvalid(r, "principal per-call zero"); // R6

        r = _rules2();
        r.terms.assets[1].maxPerCall = uint256(MARKER_PRINCIPAL);
        _expectInvalid(r, "marker off principal asset"); // R7: per-call
        r = _rules2();
        r.terms.assets[1].maxTotal = uint256(MARKER_PRINCIPAL);
        _expectInvalid(r, "principal per-call zero"); // a second principal, with a zero per-call cap
        r.terms.assets[1].maxPerCall = 5;
        _expectRule(r, abi.encodeWithSelector(UniversalMarketplaceErrors.ManyPrincipals.selector)); // R5: two

        // the principal on asset 1 instead: asset 0 then carries no marker
        r = _rules2();
        r.terms.assets[1] = AssetCap({token: pethPrc20, maxPerCall: 5, maxTotal: uint256(MARKER_PRINCIPAL)});
        r.terms.assets[0] = AssetCap({token: usdcPrc20, maxPerCall: uint256(MARKER_PRINCIPAL), maxTotal: 0});
        _expectInvalid(r, "marker off principal asset");
        r.terms.assets[0] = AssetCap({token: usdcPrc20, maxPerCall: 0, maxTotal: 0});
        _validate(r);

        // a tranche card: a fixed per-call cap passes
        r = _rules();
        r.terms.assets[0].maxPerCall = 100;
        _validate((r));
    }

    function test_MT04_allowListAndPins() public {
        _expectInvalid(_withCalls(new AllowedCall[](0)), "allow-list size"); // R8
        _expectInvalid(_withCalls(_manyCalls(33)), "allow-list size");
        _validate((_withCalls(_manyCalls(32)))); // boundary

        AllowedCall[] memory c = _manyCalls(1);
        c[0].pins = _distinctPins(9);
        _expectInvalid(_withCalls(c), "too many pins"); // R9: one call over MAX_PINS
        c[0].pins = _distinctPins(8);
        _validate((_withCalls(c))); // boundary

        c = _manyCalls(5); // 8 + 8 + 8 + 8 + 1 = 33 pins in all
        for (uint256 i; i < 4; ++i) {
            c[i].pins = _distinctPins(8);
        }
        c[4].pins = _distinctPins(1);
        _expectInvalid(_withCalls(c), "too many pins"); // R9: total over MAX_ALLOWED_CALL_PINS
        c[4].pins = _noPins();
        _validate((_withCalls(c))); // 32 in all: boundary

        CardRule memory r = _rules();
        r.terms.allowedCalls[1].pins[0].op = PinOp.MAX;
        _expectInvalid(r, "wallet marker op"); // R10
    }

    function test_MT05_duplicates() public {
        CardRule memory r = _rules();
        AllowedCall memory supply = r.terms.allowedCalls[1];
        _expectInvalid(_withCalls(_calls2(supply, supply)), "duplicate call"); // R11

        AllowedCall memory pinless = _allowed(pool, SUPPLY, 0, false, _noPins());
        _expectInvalid(_withCalls(_calls2(supply, pinless)), "unpinned duplicate"); // R12: either order
        _expectInvalid(_withCalls(_calls2(pinless, supply)), "unpinned duplicate");
        AllowedCall memory pinless2 = _allowed(pool, SUPPLY, 4, true, _noPins());
        _expectInvalid(_withCalls(_calls2(pinless, pinless2)), "unpinned duplicate"); // both pinless

        // "approve to Aave or Uniswap": same (target, selector), different pins
        AllowedCall memory toAave = _approveTo(pool, PinOp.MAX, MARKER_PRINCIPAL);
        AllowedCall memory toUni = _approveTo(makeAddr("uniswap"), PinOp.MAX, MARKER_PRINCIPAL);
        _validate((_withCalls(_calls2(toAave, toUni))));
    }

    function test_MT06_erc20Rules() public {
        // R13
        _expectInvalid(
            _withCalls(_calls1(_allowed(usdc, INCREASE_ALLOWANCE, 4, true, _pins1(4, PinOp.EQ, _word(pool))))),
            "increaseAllowance"
        );

        // R14: spender pin missing, zero, dirty high bits, or a marker
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, APPROVE, 0, false, _pins1(36, PinOp.MAX, bytes32(uint256(1)))))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedApprove.selector, 0, 0)
        );
        bytes32[4] memory badSpenders =
            [bytes32(0), bytes32(uint256(1) << 160 | uint160(pool)), MARKER_WALLET, MARKER_PRINCIPAL];
        for (uint256 i; i < 4; ++i) {
            AllowedCall memory a = _approveTo(pool, PinOp.MAX, bytes32(uint256(1)));
            a.pins[0].value = badSpenders[i];
            _expectRule(
                _withCalls(_calls1(a)),
                abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedApprove.selector, 0, 0)
            );
        }
        AllowedCall memory spenderAsMax = _approveTo(pool, PinOp.MAX, bytes32(uint256(1)));
        spenderAsMax.pins[0].op = PinOp.MAX;
        _expectRule(
            _withCalls(_calls1(spenderAsMax)),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedApprove.selector, 0, 0)
        );

        // R15: amount pin missing, or under EQ
        _expectInvalid(
            _withCalls(_calls1(_allowed(usdc, APPROVE, 0, false, _pins1(4, PinOp.EQ, _word(pool))))),
            "approve amount not capped"
        );
        _expectInvalid(
            _withCalls(_calls1(_approveTo(pool, PinOp.EQ, bytes32(uint256(1))))), "approve amount not capped"
        );

        // approve passes with a MAX literal and with MAX MARKER_PRINCIPAL; required pins may sit anywhere
        _validate((_withCalls(_calls1(_approveTo(pool, PinOp.MAX, bytes32(uint256(7)))))));
        _validate((_withCalls(_calls1(_approveTo(pool, PinOp.MAX, MARKER_PRINCIPAL)))));
        AllowedCall memory reordered = _approveTo(pool, PinOp.MAX, MARKER_PRINCIPAL);
        (reordered.pins[0], reordered.pins[1]) = (reordered.pins[1], reordered.pins[0]);
        _validate((_withCalls(_calls1(reordered))));

        // R16 / R17: refused without the recipient bound, at the right offset
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER, 4, false, _noPins()))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER, 36, true, _noPins()))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER, 0, false, _pins1(36, PinOp.EQ, MARKER_WALLET)))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER, 0, false, _pins1(4, PinOp.EQ, _word(cea))))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER_FROM, 36, false, _noPins()))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER_FROM, 4, true, _noPins()))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );
        _expectRule(
            _withCalls(_calls1(_allowed(usdc, TRANSFER_FROM, 0, false, _pins1(4, PinOp.EQ, MARKER_WALLET)))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 0, 0)
        );

        // pass with the beneficiary field, and with an EQ MARKER_WALLET pin
        _validate(
            _withCalls(
                _calls2(
                    _allowed(usdc, TRANSFER, 4, true, _noPins()), _allowed(usdc, TRANSFER_FROM, 36, true, _noPins())
                )
            )
        );
        _validate(
            _withCalls(
                _calls2(
                    _allowed(usdc, TRANSFER, 0, false, _pins1(4, PinOp.EQ, MARKER_WALLET)),
                    _allowed(usdc, TRANSFER_FROM, 0, false, _pins1(36, PinOp.EQ, MARKER_WALLET))
                )
            )
        );
    }

    // ═════════════════════════════ checkRulesMatchCard ═════════════════════════════

    function test_MT07_match_happy() public {
        rules.checkRulesMatchCard(_enc(_rules()), _sessions(_sessionFor(_terms(_rules()))), _ctx());
        rules.checkRulesMatchCard(_enc(_rules2()), _sessions(_sessionFor(_terms(_rules2()))), _ctx());

        CardRule memory tranche = _rules2();
        tranche.terms.assets[0].maxPerCall = 100e6; // per-call fixed
        UniversalTerms memory t = _terms(tranche);
        assertEq(t.assets[0].maxPerCall, 100e6, "fixed per-call is copied, not filled");
        assertEq(t.assets[0].maxTotal, PRINCIPAL);
        rules.checkRulesMatchCard(_enc(tranche), _sessions(_sessionFor(t)), _ctx());
    }

    function _expectMatch(CardRule memory r, Session memory s, bytes memory err) internal {
        bytes memory enc = _enc(r);
        Session[] memory ss = _sessions(s);
        SessionContext memory ctx = _ctx();
        vm.expectRevert(err);
        rules.checkRulesMatchCard(enc, ss, ctx);
    }

    function _expectTerms(UniversalTerms memory t, bytes memory err) internal {
        _expectMatch(_rules2(), _sessionFor(t), err);
    }

    function test_MT08_match_eachError() public {
        CardRule memory r = _rules2();
        bytes memory actionsMismatch = abi.encodeWithSelector(UniversalMarketplaceErrors.ActionsMismatch.selector, 0);

        // C1
        Session memory s = _sessionFor(_terms(r));
        s.sessionValidatorInitData = abi.encode(makeAddr("other"));
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.AgentMismatch.selector, 0));
        s.sessionValidatorInitData = abi.encodePacked(agent); // 20 bytes: not the 32-byte agent config
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.AgentMismatch.selector, 0));

        // C2
        s = _sessionFor(_terms(r));
        s.actions = new ActionData[](0);
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.ActionCount.selector, 0));
        s = _sessionFor(_terms(r));
        ActionData[] memory two = new ActionData[](2);
        (two[0], two[1]) = (s.actions[0], s.actions[0]);
        s.actions = two;
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.ActionCount.selector, 0));

        // C3
        s = _sessionFor(_terms(r));
        s.actions[0].actionPolicies = new PolicyData[](0);
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.PolicyShape.selector, 0));
        s = _sessionFor(_terms(r));
        PolicyData[] memory twoPolicies = new PolicyData[](2);
        (twoPolicies[0], twoPolicies[1]) = (s.actions[0].actionPolicies[0], s.actions[0].actionPolicies[0]);
        s.actions[0].actionPolicies = twoPolicies;
        _expectMatch(r, s, abi.encodeWithSelector(UniversalMarketplaceErrors.PolicyShape.selector, 0));

        // C4: pre-v6 two-field envelope (first word = 64, the string's offset), version 2, and under one word
        bytes memory body = abi.encode(_terms(r));
        _expectMatch(
            r,
            _session(abi.encode(SEPOLIA, body)),
            abi.encodeWithSelector(UniversalMarketplaceErrors.EnvelopeVersionMismatch.selector, 0, 64)
        );
        _expectMatch(
            r,
            _session(abi.encode(uint16(2), SEPOLIA, body)),
            abi.encodeWithSelector(UniversalMarketplaceErrors.EnvelopeVersionMismatch.selector, 0, 2)
        );
        _expectMatch(
            r,
            _session(new bytes(31)),
            abi.encodeWithSelector(UniversalMarketplaceErrors.EnvelopeVersionMismatch.selector, 0, 0)
        );

        // C5
        _expectMatch(
            r,
            _session(_envelope(_terms(r), "eip155:1")),
            abi.encodeWithSelector(UniversalMarketplaceErrors.ChainMismatch.selector, 0)
        );

        // C6: the card has two assets; the session one
        UniversalTerms memory t = _terms(_rules());
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetCountMismatch.selector, 0, 2, 1));

        // C7: each index
        t = _terms(r);
        t.assets[0].token = usdc;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));
        t = _terms(r);
        t.assets[1].token = usdc;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 1));

        // C8
        t = _terms(r);
        t.assets[0].maxTotal = PRINCIPAL + 1;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));
        t = _terms(r);
        t.assets[0].maxPerCall = PRINCIPAL - 1;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));

        // C9: each field of the non-principal asset
        t = _terms(r);
        t.assets[1].maxPerCall = 1;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 1));
        t = _terms(r);
        t.assets[1].maxTotal = 1;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 1));

        // C10
        t = _terms(r);
        t.maxGasPerCall = 0;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.GasCapMismatch.selector, 0));

        // C11: length, then every call field, then every pin's offset and op
        t = _terms(r);
        AllowedCall[] memory shorter = new AllowedCall[](2);
        (shorter[0], shorter[1]) = (t.allowedCalls[0], t.allowedCalls[1]);
        t.allowedCalls = shorter;
        _expectTerms(t, actionsMismatch);
        for (uint256 f; f < 8; ++f) {
            t = _terms(r);
            AllowedCall memory c = t.allowedCalls[0];
            if (f == 0) c.target = pool;
            if (f == 1) c.selector = TRANSFER;
            if (f == 2) c.beneficiaryOffset = 4;
            if (f == 3) c.hasBeneficiary = true;
            if (f == 4) c.maxValue = 1;
            if (f == 5) c.pins = _pins1(4, PinOp.EQ, _word(pool));
            if (f == 6) c.pins[1].offset = 68;
            if (f == 7) c.pins[1].op = PinOp.EQ;
            _expectTerms(t, actionsMismatch);
        }

        // C13
        t = _terms(r);
        t.validUntil = EXPIRY - 1;
        _expectTerms(t, abi.encodeWithSelector(UniversalMarketplaceErrors.ExpiryMismatch.selector, 0));

        // C14
        t = _terms(r);
        t.expectedCEA = address(0xBAD);
        t.allowedCalls[1].pins[0].value = _word(address(0xBAD)); // keep C12 satisfied for the bad CEA
        SessionContext memory ctx = _ctx();
        bytes memory enc = _enc(r);
        Session[] memory bad = _sessions(_sessionFor(t));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 1, 0));
        rules.checkRulesMatchCard(enc, bad, ctx); // C12 runs before C14: the pin is checked against ctx's CEA
        t.allowedCalls[1].pins[0].value = _word(cea);
        bad = _sessions(_sessionFor(t));
        vm.expectRevert(
            abi.encodeWithSelector(UniversalMarketplaceErrors.ExpectedCEAMismatch.selector, 0, cea, address(0xBAD))
        );
        rules.checkRulesMatchCard(enc, bad, ctx);
    }

    function test_MT09_match_pins() public {
        CardRule memory r = _rules();

        UniversalTerms memory t = _terms(r);
        t.allowedCalls[1].pins[0].value = _word(makeAddr("otherCEA")); // MARKER_WALLET, wrong CEA
        _expectMatch(
            r, _sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 1, 0)
        );

        t = _terms(r);
        t.allowedCalls[0].pins[1].value = bytes32(PRINCIPAL - 1); // MARKER_PRINCIPAL, principal − 1
        _expectMatch(
            r, _sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 0, 1)
        );

        t = _terms(r);
        t.allowedCalls[0].pins[0].value = _word(makeAddr("otherSpender")); // a changed literal
        _expectMatch(
            r, _sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 0, 0)
        );

        t = _terms(r);
        t.allowedCalls[1].pins[0].value = MARKER_WALLET; // the raw marker, unfilled
        _expectMatch(
            r, _sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 1, 0)
        );
        t = _terms(r);
        t.allowedCalls[0].pins[1].value = MARKER_PRINCIPAL;
        _expectMatch(
            r, _sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 0, 0, 1)
        );
    }

    /// @dev Malformed bytes fail in `abi.decode`, which reverts with no data: a bare expectRevert is the only
    ///      way to name it. Each case is otherwise well formed, so nothing else can be what reverts.
    function test_MT10_malformedInputs() public {
        vm.expectRevert();
        rules.validateAgentCardRules(hex"01", MAX_RULES);

        bytes memory enc = _enc(_rules());
        SessionContext memory ctx = _ctx();
        Session[] memory badEnvelope = _sessions(_session(abi.encodePacked(uint256(1), hex"01"))); // version, garbage
        vm.expectRevert();
        rules.checkRulesMatchCard(enc, badEnvelope, ctx);

        Session[] memory badBody = _sessions(_session(abi.encode(uint16(1), SEPOLIA, hex"01")));
        vm.expectRevert();
        rules.checkRulesMatchCard(enc, badBody, ctx);

        Session[] memory good = _sessions(_sessionFor(_terms(_rules())));
        vm.expectRevert();
        rules.checkRulesMatchCard(hex"01", good, ctx);
    }

    function testFuzz_MT11_principalBinding(uint256 principal) public {
        principal = bound(principal, 1, 1e30);
        CardRule memory r = _rules2();
        bytes memory enc = _enc(r);
        SessionContext memory ctx = _ctx();
        ctx.principal = principal;
        rules.checkRulesMatchCard(enc, _sessions(_sessionFor(_fillTerms(r, principal, EXPIRY, cea))), ctx);

        UniversalTerms memory t = _fillTerms(r, principal, EXPIRY, cea);
        t.assets[0].maxTotal = principal + 1;
        Session[] memory s = _sessions(_sessionFor(t));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));
        rules.checkRulesMatchCard(enc, s, ctx);

        t = _fillTerms(r, principal, EXPIRY, cea);
        t.assets[0].maxTotal = principal - 1;
        s = _sessions(_sessionFor(t));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));
        rules.checkRulesMatchCard(enc, s, ctx);

        t = _fillTerms(r, principal, EXPIRY, cea);
        t.assets[0].maxPerCall = principal + 1;
        s = _sessions(_sessionFor(t));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector, 0, 0));
        rules.checkRulesMatchCard(enc, s, ctx);
    }

    // ═════════════════════════════ several rules (one per chain) ═════════════════════════════

    address internal baseCea = makeAddr("cea.base");

    function _four() internal returns (CardRule[] memory rs) {
        rs = new CardRule[](4);
        rs[0] = _rules();
        rs[1] = _baseRule();
        rs[2] = _sideRule(ARBITRUM, makeAddr("pETH.arb"), makeAddr("pool.arb"));
        rs[3] = _sideRule(BSC, makeAddr("pBNB.bsc"), makeAddr("pool.bsc"));
    }

    function _expectRules(CardRule[] memory rs, uint256 maxRules, bytes memory err) internal {
        bytes memory enc = abi.encode(rs);
        vm.expectRevert(err);
        rules.validateAgentCardRules(enc, maxRules);
    }

    function test_MT12_ruleCount() public {
        _expectRules(
            new CardRule[](0), MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.RulesEmpty.selector)
        );
        CardRule[] memory two = _rulesOf(_rules(), _baseRule());
        _expectRules(two, 1, abi.encodeWithSelector(UniversalMarketplaceErrors.TooManyRules.selector, 2, 1));
        rules.validateAgentCardRules(abi.encode(two), 2); // boundary

        CardRule[] memory four = _four();
        (bytes32[] memory chains, address[] memory tokens, bytes32[] memory tokenChains) =
            rules.validateAgentCardRules(abi.encode(four), MAX_RULES);
        assertEq(chains.length, 4);
        assertEq(chains[0], SEPOLIA_HASH);
        assertEq(chains[1], BASE_HASH);
        assertEq(chains[2], ARBITRUM_HASH);
        assertEq(chains[3], BSC_HASH);
        assertEq(tokens.length, 4);
        assertEq(tokens[1], makeAddr("pETH.base"));
        assertEq(tokenChains[1], BASE_HASH, "each token carries its own rule's chain");

        CardRule[] memory five = new CardRule[](5);
        for (uint256 i; i < 4; ++i) {
            five[i] = four[i];
        }
        five[4] = _sideRule("eip155:1", makeAddr("pETH.eth"), makeAddr("pool.eth"));
        _expectRules(five, MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.TooManyRules.selector, 5, 4));
    }

    function test_MT13_chainAndBlankFields() public {
        CardRule[] memory rs = _rulesOf(_rules(), _baseRule());
        rs[1].chainNamespace = "eip155:";
        _expectRules(
            rs,
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.InvalidAgentCard.selector, "chain namespace")
        );
        rs[1].chainNamespace = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
        _expectRules(
            rs,
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.InvalidAgentCard.selector, "chain namespace")
        );
        rs[1].chainNamespace = SEPOLIA;
        _expectRules(rs, MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.DuplicateChain.selector, 1));

        rs = _rulesOf(_rules(), _baseRule());
        rs[1].terms.validUntil = 1;
        _expectRules(rs, MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.RuleHasAgent.selector, 1));
        rs = _rulesOf(_rules(), _baseRule());
        rs[0].terms.expectedCEA = cea;
        _expectRules(rs, MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.RuleHasAgent.selector, 0));
    }

    function test_MT14_principalAcrossRules() public {
        // the principal may sit in any rule
        CardRule memory side = _rules();
        side.terms.assets[0] = AssetCap({token: usdcPrc20, maxPerCall: 1, maxTotal: 1});
        side.terms.allowedCalls[0].pins[1].value = bytes32(uint256(1)); // no principal anywhere in this rule
        CardRule memory principalOnBase = _baseRule();
        principalOnBase.terms.assets[0].maxTotal = uint256(MARKER_PRINCIPAL);
        rules.validateAgentCardRules(abi.encode(_rulesOf(side, principalOnBase)), MAX_RULES);

        // one in each rule: two principals
        CardRule[] memory both = _rulesOf(_rules(), principalOnBase);
        _expectRules(both, MAX_RULES, abi.encodeWithSelector(UniversalMarketplaceErrors.ManyPrincipals.selector));
        // in neither
        _expectRules(
            _rulesOf(side, _baseRule()),
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.NoPrincipal.selector)
        );
        // the marker on a non-principal asset of another rule
        CardRule memory markedBase = _baseRule();
        markedBase.terms.assets[0].maxPerCall = uint256(MARKER_PRINCIPAL);
        _expectRules(
            _rulesOf(_rules(), markedBase),
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.InvalidAgentCard.selector, "marker off principal asset")
        );
    }

    function test_MT15_erc20ErrorsNameRuleAndCall() public {
        CardRule memory base = _baseRule();
        AllowedCall[] memory calls = new AllowedCall[](2);
        calls[0] = base.terms.allowedCalls[0];
        calls[1] = _allowed(usdc, APPROVE, 0, false, _pins1(36, PinOp.MAX, bytes32(uint256(1))));
        base.terms.allowedCalls = calls;
        _expectRules(
            _rulesOf(_rules(), base),
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedApprove.selector, 1, 1)
        );
        calls[1] = _allowed(usdc, TRANSFER, 0, false, _pins1(4, PinOp.EQ, _word(makeAddr("provider"))));
        _expectRules(
            _rulesOf(_rules(), base),
            MAX_RULES,
            abi.encodeWithSelector(UniversalMarketplaceErrors.UnpinnedTransfer.selector, 1, 1)
        );
    }

    function _ctx2() internal view returns (SessionContext memory c) {
        c = _ctx();
        c.expectedCEAs = new address[](2);
        (c.expectedCEAs[0], c.expectedCEAs[1]) = (cea, baseCea);
    }

    function _baseSession(UniversalTerms memory t) internal returns (Session memory) {
        return _session(_envelope(t, BASE));
    }

    function test_MT16_matchPerPair() public {
        CardRule memory base = _baseRule();
        bytes memory enc = abi.encode(_rulesOf(_rules(), base));
        UniversalTerms memory tBase = _fillTerms(base, PRINCIPAL, EXPIRY, baseCea);
        assertEq(tBase.allowedCalls[0].pins[0].value, _word(baseCea), "MARKER_WALLET on Base is the Base CEA");
        Session memory sSep = _sessionFor(_terms(_rules()));
        Session memory sBase = _baseSession(tBase);
        SessionContext memory ctx = _ctx2();
        rules.checkRulesMatchCard(enc, _sessions(sSep, sBase), ctx);

        // one session for two rules
        Session[] memory one = _sessions(sSep);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.SessionCountMismatch.selector, 2, 1));
        rules.checkRulesMatchCard(enc, one, ctx);

        // swapped order: pair 0 is the Base session on the Sepolia rule
        Session[] memory swapped = _sessions(sBase, sSep);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.ChainMismatch.selector, 0));
        rules.checkRulesMatchCard(enc, swapped, ctx);

        // a mismatch in the second pair names index 1
        UniversalTerms memory bad = _fillTerms(base, PRINCIPAL, EXPIRY, baseCea);
        bad.maxGasPerCall = 1;
        Session[] memory ss = _sessions(sSep, _baseSession(bad));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.GasCapMismatch.selector, 1));
        rules.checkRulesMatchCard(enc, ss, ctx);

        // the Base rule's wallet pin filled with the Sepolia CEA
        bad = _fillTerms(base, PRINCIPAL, EXPIRY, cea);
        ss = _sessions(sSep, _baseSession(bad));
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.PinMismatch.selector, 1, 0, 0));
        rules.checkRulesMatchCard(enc, ss, ctx);
    }
}
