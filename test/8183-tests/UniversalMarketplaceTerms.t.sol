// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {UniversalMarketplaceTerms} from "../../src/agentic-commerce-8183/UniversalMarketplaceTerms.sol";
import {UniversalMarketplaceErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";
import {
    Session,
    ActionData,
    PolicyData,
    ERC7739Data,
    ERC7739Context,
    AllowedCall,
    UniversalTerms
} from "../../src/agentic-commerce-8183/interfaces/external/IAGW.sol";
import {Approval, RulesCardTerms, SessionContext} from "../../src/agentic-commerce-8183/libraries/Types.sol";

/// @title UniversalMarketplaceTerms — unit suite (PRD 09 §7.3). Direct calls; the marketplace suite covers the
///        same rules through `registerCard` and `startJob`.
contract UniversalMarketplaceTermsTest is Test {
    UniversalMarketplaceTerms internal terms;

    address internal agent = makeAddr("agent");
    address internal asset = makeAddr("pUSDC.sepolia");
    address internal pool = makeAddr("pool");
    address internal usdc = makeAddr("USDC");
    address internal cea = makeAddr("cea");
    address internal validator = makeAddr("validator");
    address internal urp = makeAddr("urp");
    bytes32 internal constant SEPOLIA_HASH = keccak256("eip155:11155111");
    uint256 internal constant PRINCIPAL = 500e6;
    uint48 internal constant EXPIRY = 1_800_000_000;

    bytes4 internal constant SUPPLY = bytes4(keccak256("supply(address,uint256,address,uint16)"));
    bytes4 internal constant TRANSFER = 0xa9059cbb;
    bytes4 internal constant APPROVE = 0x095ea7b3;
    bytes4 internal constant TRANSFER_FROM = 0x23b872dd;
    bytes4 internal constant INCREASE_ALLOWANCE = 0x39509351;

    function setUp() public {
        terms = new UniversalMarketplaceTerms();
    }

    // ───────── builders ─────────

    function _call(address target, bytes4 selector, uint16 offset, bool pinned)
        internal
        pure
        returns (AllowedCall memory)
    {
        return AllowedCall({
            target: target, selector: selector, beneficiaryOffset: offset, hasBeneficiary: pinned, maxValue: 0
        });
    }

    function _rules() internal view returns (RulesCardTerms memory r) {
        r.asset = asset;
        r.maxPCPerCall = 1 ether;
        r.allowedCalls = new AllowedCall[](1);
        r.allowedCalls[0] = _call(pool, SUPPLY, 68, true);
        r.approvals = new Approval[](1);
        r.approvals[0] = Approval({token: usdc, spender: pool, capIsPrincipal: true, cap: 0});
    }

    function _terms() internal view returns (UniversalTerms memory t) {
        RulesCardTerms memory r = _rules();
        t.validUntil = EXPIRY;
        t.expectedCEA = cea;
        t.asset = r.asset;
        t.maxAmountPerCall = PRINCIPAL;
        t.maxAmountTotal = PRINCIPAL;
        t.maxPCPerCall = r.maxPCPerCall;
        t.allowedCalls = r.allowedCalls;
    }

    function _session(bytes memory initData) internal view returns (Session memory s) {
        s.sessionValidator = validator;
        s.sessionValidatorInitData = abi.encode(agent);
        s.erc7739Policies =
            ERC7739Data({allowedERC7739Content: new ERC7739Context[](0), erc1271Policies: new PolicyData[](0)});
        PolicyData[] memory p = new PolicyData[](1);
        p[0] = PolicyData({policy: urp, initData: initData});
        s.actions = new ActionData[](1);
        s.actions[0] = ActionData({actionTargetSelector: bytes4(0x12345678), actionTarget: pool, actionPolicies: p});
    }

    function _sessionFor(UniversalTerms memory t) internal view returns (Session memory) {
        return _session(abi.encode("eip155:11155111", abi.encode(t)));
    }

    function _ctx() internal view returns (SessionContext memory) {
        return SessionContext({
            agent: agent, chainHash: SEPOLIA_HASH, principal: PRINCIPAL, expiredAt: EXPIRY, expectedCEA: cea
        });
    }

    function _expectInvalid(RulesCardTerms memory r, string memory reason) internal {
        bytes memory enc = abi.encode(r);
        vm.expectRevert(abi.encodeWithSelector(UniversalMarketplaceErrors.InvalidCard.selector, reason));
        terms.validateRulesTerms(enc);
    }

    function _withCalls(AllowedCall[] memory calls) internal view returns (RulesCardTerms memory r) {
        r = _rules();
        r.allowedCalls = calls;
    }

    function _one(AllowedCall memory c) internal pure returns (AllowedCall[] memory calls) {
        calls = new AllowedCall[](1);
        calls[0] = c;
    }

    // ═════════════════════════════ validateRulesTerms ═════════════════════════════

    function test_MT01_validateRulesTerms_returnsAsset() public view {
        assertEq(terms.validateRulesTerms(abi.encode(_rules())), asset);
        RulesCardTerms memory r = _rules();
        r.approvals = new Approval[](0); // approvals are optional
        assertEq(terms.validateRulesTerms(abi.encode(r)), asset);
    }

    function test_MT02_allowList() public {
        RulesCardTerms memory r = _rules();
        r.asset = address(0);
        _expectInvalid(r, "asset zero");

        _expectInvalid(_withCalls(new AllowedCall[](0)), "allow-list size");
        AllowedCall[] memory many = new AllowedCall[](33);
        for (uint256 i; i < 33; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            many[i] = _call(address(uint160(0x1000 + i)), SUPPLY, 68, true); // i < 33: a small distinct address
        }
        _expectInvalid(_withCalls(many), "allow-list size");

        AllowedCall[] memory dup = new AllowedCall[](2);
        dup[0] = _call(pool, SUPPLY, 68, true);
        dup[1] = _call(pool, SUPPLY, 4, false); // same (target, selector), other fields differ
        _expectInvalid(_withCalls(dup), "duplicate call");

        _expectInvalid(_withCalls(_one(_call(usdc, APPROVE, 4, true))), "erc20 approval");
        _expectInvalid(_withCalls(_one(_call(usdc, INCREASE_ALLOWANCE, 4, true))), "erc20 approval");
        _expectInvalid(_withCalls(_one(_call(usdc, TRANSFER, 36, true))), "erc20 transfer recipient");
        _expectInvalid(_withCalls(_one(_call(usdc, TRANSFER, 4, false))), "erc20 transfer recipient");
        _expectInvalid(_withCalls(_one(_call(usdc, TRANSFER_FROM, 4, true))), "erc20 transferFrom recipient");
        _expectInvalid(_withCalls(_one(_call(usdc, TRANSFER_FROM, 36, false))), "erc20 transferFrom recipient");

        // boundaries pass: 32 calls; transfer pinned at 4; transferFrom pinned at 36
        AllowedCall[] memory max = new AllowedCall[](32);
        for (uint256 i; i < 32; ++i) {
            max[i] = many[i];
        }
        terms.validateRulesTerms(abi.encode(_withCalls(max)));
        AllowedCall[] memory erc20 = new AllowedCall[](2);
        erc20[0] = _call(usdc, TRANSFER, 4, true);
        erc20[1] = _call(usdc, TRANSFER_FROM, 36, true);
        terms.validateRulesTerms(abi.encode(_withCalls(erc20)));
    }

    function _withApprovals(Approval[] memory a) internal view returns (RulesCardTerms memory r) {
        r = _rules();
        r.approvals = a;
    }

    function _approvals(uint256 n) internal pure returns (Approval[] memory a) {
        a = new Approval[](n);
        for (uint256 i; i < n; ++i) {
            a[i] = Approval({
                // forge-lint: disable-next-line(unsafe-typecast)
                token: address(uint160(0x2000 + i)), // i < 9: a small distinct address
                spender: address(0xB0B),
                capIsPrincipal: i % 2 == 0,
                cap: i % 2
            });
        }
    }

    function test_MT03_approvals() public {
        _expectInvalid(_withApprovals(_approvals(9)), "approval count");

        Approval[] memory a = _approvals(1);
        a[0].token = address(0);
        _expectInvalid(_withApprovals(a), "approval token");
        a = _approvals(1);
        a[0].spender = address(0);
        _expectInvalid(_withApprovals(a), "approval spender");
        a = _approvals(1);
        a[0].cap = 1; // capIsPrincipal with a cap
        _expectInvalid(_withApprovals(a), "approval cap");
        a = _approvals(2);
        a[1].cap = 0; // a fixed cap of zero
        _expectInvalid(_withApprovals(a), "approval cap");
        a = _approvals(2);
        a[1].token = a[0].token; // same (token, spender)
        a[1].capIsPrincipal = true;
        a[1].cap = 0;
        _expectInvalid(_withApprovals(a), "duplicate approval");

        terms.validateRulesTerms(abi.encode(_withApprovals(_approvals(8))));
    }

    // ═════════════════════════════ verifySession ═════════════════════════════

    function test_MT04_verifySession_happy() public view {
        terms.verifySession(abi.encode(_rules()), _sessionFor(_terms()), _ctx());
        UniversalTerms memory t = _terms();
        t.maxAmountPerCall = 1; // below principal is fine
        terms.verifySession(abi.encode(_rules()), _sessionFor(t), _ctx());
    }

    function _expectSession(Session memory s, bytes memory err) internal {
        bytes memory r = abi.encode(_rules());
        vm.expectRevert(err);
        terms.verifySession(r, s, _ctx());
    }

    function test_MT05_verifySession_eachError() public {
        Session memory s = _sessionFor(_terms());
        s.sessionValidatorInitData = abi.encode(makeAddr("other"));
        _expectSession(s, abi.encodeWithSelector(UniversalMarketplaceErrors.AgentMismatch.selector));
        s.sessionValidatorInitData = abi.encodePacked(agent); // 20 bytes: not the 32-byte agent config
        _expectSession(s, abi.encodeWithSelector(UniversalMarketplaceErrors.AgentMismatch.selector));

        s = _sessionFor(_terms());
        s.actions = new ActionData[](0);
        _expectSession(s, abi.encodeWithSelector(UniversalMarketplaceErrors.ActionCount.selector));
        s = _sessionFor(_terms());
        ActionData[] memory two = new ActionData[](2);
        (two[0], two[1]) = (s.actions[0], s.actions[0]);
        s.actions = two;
        _expectSession(s, abi.encodeWithSelector(UniversalMarketplaceErrors.ActionCount.selector));

        s = _sessionFor(_terms());
        s.actions[0].actionPolicies = new PolicyData[](0);
        _expectSession(s, abi.encodeWithSelector(UniversalMarketplaceErrors.PolicyShape.selector, 0));
        _expectSession(
            _session(abi.encode("eip155:1", abi.encode(_terms()))),
            abi.encodeWithSelector(UniversalMarketplaceErrors.ChainMismatch.selector, 0)
        );

        UniversalTerms memory t = _terms();
        t.asset = usdc;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.AssetMismatch.selector));
        t = _terms();
        t.maxPCPerCall = 0;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.PCCapMismatch.selector));
        t = _terms();
        t.allowedCalls[0].beneficiaryOffset = 36;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.ActionsMismatch.selector));
        t = _terms();
        t.maxAmountTotal = PRINCIPAL + 1;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.CapMismatch.selector));
        t = _terms();
        t.maxAmountPerCall = PRINCIPAL + 1;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.CapMismatch.selector));
        t = _terms();
        t.validUntil = EXPIRY - 1;
        _expectSession(_sessionFor(t), abi.encodeWithSelector(UniversalMarketplaceErrors.ExpiryMismatch.selector));
        t = _terms();
        t.expectedCEA = address(0xBAD);
        _expectSession(
            _sessionFor(t),
            abi.encodeWithSelector(UniversalMarketplaceErrors.ExpectedCEAMismatch.selector, cea, address(0xBAD))
        );
    }

    /// @dev Malformed bytes fail in `abi.decode`, which reverts with no data: a bare expectRevert is the only
    ///      way to name it. Each case is otherwise well formed, so nothing else can be what reverts.
    function test_MT06_malformedInputs() public {
        vm.expectRevert();
        terms.validateRulesTerms(hex"01");

        bytes memory r = abi.encode(_rules());
        Session memory badEnvelope = _session(hex"01");
        vm.expectRevert();
        terms.verifySession(r, badEnvelope, _ctx());

        Session memory badBody = _session(abi.encode("eip155:11155111", hex"01"));
        vm.expectRevert();
        terms.verifySession(r, badBody, _ctx());

        Session memory good = _sessionFor(_terms());
        vm.expectRevert();
        terms.verifySession(hex"01", good, _ctx());
    }

    function testFuzz_MT07_caps(uint256 perCall, uint256 total) public {
        perCall = bound(perCall, 0, PRINCIPAL * 2);
        total = bound(total, 0, PRINCIPAL * 2);
        UniversalTerms memory t = _terms();
        t.maxAmountPerCall = perCall;
        t.maxAmountTotal = total;
        bytes memory r = abi.encode(_rules());
        Session memory s = _sessionFor(t);
        if (perCall <= PRINCIPAL && total == PRINCIPAL) {
            terms.verifySession(r, s, _ctx());
        } else {
            vm.expectRevert(UniversalMarketplaceErrors.CapMismatch.selector);
            terms.verifySession(r, s, _ctx());
        }
    }
}
