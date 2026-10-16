// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    AllowedMutability,
    ReadAt,
    T_TUPLE,
    T_UINT
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Multicall, MULTICALL_SELECTOR} from "../../../src/libraries/Types.sol";

interface IWETH {
    function deposit() external payable;
}

/// @title Demo — the three demo jobs: addresses, criteria and the CEA's work
/// @notice Job 1 · Aave ETH Supplier: all of the ETH supplied to Aave on Base Sepolia, nothing idle.
///         Job 2 · Yield Splitter: the ETH split between Aave and the Morpho-style vault on Base Sepolia, at least
///                 30% in each, nothing idle.
///         Job 3 · Cross-Chain Diversifier: the ETH supplied to Aave on Base Sepolia and Ethereum Sepolia, no more
///                 than 60% on either chain, nothing idle.
/// @dev Official Aave v3 testnet deployments; the vault is ours (`src/mocks/DemoMorphoVault.sol`). All amounts are
///      WETH wei. The CEA receives the principal as native ETH with the outbound and wraps it itself.
library Demo {
    // ───────── chains ─────────
    string internal constant NS = "eip155";
    string internal constant BASE_ID = "84532";
    string internal constant SEP_ID = "11155111";

    // ───────── Base Sepolia ─────────
    address internal constant BASE_POOL = 0x8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27;
    address internal constant BASE_WETH = 0x4200000000000000000000000000000000000006;
    address internal constant BASE_AWETH = 0x73a5bB60b0B0fc35710DDc0ea9c407031E31Bdbb;

    // ───────── Ethereum Sepolia ─────────
    address internal constant SEP_POOL = 0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951;
    address internal constant SEP_WETH = 0xC558DBdd856501FCd9aaF1E62eae57A9F0629a3c;
    address internal constant SEP_AWETH = 0x5b071b590a59395fE4025A0Ccc1FcC931AAc1830;

    // ───────── Push Donut ─────────
    address internal constant GATEWAY_PC = 0x00000000000000000000000000000000000000C1;
    address internal constant PETH_BASE = 0xc7007af2B24D4eb963fc9633B0c66e1d2D90Fc21;
    address internal constant PETH_SEP = 0x2971824Db68229D087931155C2b8bB820B275809;

    /// @notice What every job is judged against: the principal and what "idle" means.
    uint256 internal constant DUST = 1e12; // 0.000001 ETH

    // ═════════════════════════ criteria ═════════════════════════

    /// @notice Job 1: aWETH grew by ≥ 99.99% of the principal; no WETH or ETH left in the CEA.
    function job1(address ceaBase, uint256 principal, uint16 conf) internal view returns (JobSpec memory s) {
        s.reads = new Read[](4);
        s.reads[0] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[1] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.PRE_EXECUTION, conf);
        s.reads[2] = _read(BASE_ID, BASE_WETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[3] = _read(BASE_ID, MULTICALL3, GET_ETH_BALANCE, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.checks = new Check[](2);
        s.checks[0] = _num(_i(0), _i(1), Operation.GREATER_OR_EQUAL, principal * 9999 / 10_000);
        s.checks[1] = _cmp(_i(2, 3), Operation.LESS_OR_EQUAL, DUST);
        _finish(s);
    }

    /// @notice Job 2: Aave + vault grew by ≥ 99.9% of the principal together, each by ≥ 30%; no WETH left.
    function job2(address ceaBase, address vault, uint256 principal, uint16 conf)
        internal
        view
        returns (JobSpec memory s)
    {
        s.reads = new Read[](5);
        s.reads[0] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[1] = _read(BASE_ID, vault, IERC4626.maxWithdraw.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[2] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.PRE_EXECUTION, conf);
        s.reads[3] = _read(BASE_ID, vault, IERC4626.maxWithdraw.selector, ceaBase, ReadAt.PRE_EXECUTION, conf);
        s.reads[4] = _read(BASE_ID, BASE_WETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.checks = new Check[](4);
        s.checks[0] = _num(_i(0, 1), _i(2, 3), Operation.GREATER_OR_EQUAL, principal * 999 / 1000);
        s.checks[1] = _num(_i(0), _i(2), Operation.GREATER_OR_EQUAL, principal * 30 / 100);
        s.checks[2] = _num(_i(1), _i(3), Operation.GREATER_OR_EQUAL, principal * 30 / 100);
        s.checks[3] = _cmp(_i(4), Operation.LESS_OR_EQUAL, DUST);
        _finish(s);
    }

    /// @notice Job 3: aWETH on both chains grew by ≥ 99.9% of the principal together, each by ≥ 40% (no more than
    ///         60% on either); no WETH left on either chain.
    function job3(address ceaBase, address ceaSep, uint256 principal, uint16 conf)
        internal
        view
        returns (JobSpec memory s)
    {
        s.reads = new Read[](6);
        s.reads[0] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[1] = _read(SEP_ID, SEP_AWETH, IERC20.balanceOf.selector, ceaSep, ReadAt.POST_EXECUTION, conf);
        s.reads[2] = _read(BASE_ID, BASE_AWETH, IERC20.balanceOf.selector, ceaBase, ReadAt.PRE_EXECUTION, conf);
        s.reads[3] = _read(SEP_ID, SEP_AWETH, IERC20.balanceOf.selector, ceaSep, ReadAt.PRE_EXECUTION, conf);
        s.reads[4] = _read(BASE_ID, BASE_WETH, IERC20.balanceOf.selector, ceaBase, ReadAt.POST_EXECUTION, conf);
        s.reads[5] = _read(SEP_ID, SEP_WETH, IERC20.balanceOf.selector, ceaSep, ReadAt.POST_EXECUTION, conf);
        s.checks = new Check[](4);
        s.checks[0] = _num(_i(0, 1), _i(2, 3), Operation.GREATER_OR_EQUAL, principal * 999 / 1000);
        s.checks[1] = _num(_i(0), _i(2), Operation.GREATER_OR_EQUAL, principal * 40 / 100);
        s.checks[2] = _num(_i(1), _i(3), Operation.GREATER_OR_EQUAL, principal * 40 / 100);
        s.checks[3] = _cmp(_i(4, 5), Operation.LESS_OR_EQUAL, DUST);
        _finish(s);
    }

    // ═════════════════════════ the CEA's work ═════════════════════════

    /// @notice Wrap `toAave + toVault` ETH, supply `toAave` to `pool` and deposit `toVault` to `vault`, both for `cea`.
    function supplyPayload(address weth, address pool, address vault, address cea, uint256 toAave, uint256 toVault)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[](1 + (toAave != 0 ? 2 : 0) + (toVault != 0 ? 2 : 0));
        uint256 i;
        calls[i++] = Multicall({to: weth, value: toAave + toVault, data: abi.encodeCall(IWETH.deposit, ())});
        if (toAave != 0) {
            calls[i++] = Multicall({to: weth, value: 0, data: abi.encodeCall(IERC20.approve, (pool, toAave))});
            calls[i++] = Multicall({
                to: pool,
                value: 0,
                data: abi.encodeWithSignature("supply(address,uint256,address,uint16)", weth, toAave, cea, uint16(0))
            });
        }
        if (toVault != 0) {
            calls[i++] = Multicall({to: weth, value: 0, data: abi.encodeCall(IERC20.approve, (vault, toVault))});
            calls[i++] = Multicall({to: vault, value: 0, data: abi.encodeCall(IERC4626.deposit, (toVault, cea))});
        }
        return abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));
    }

    // ═════════════════════════ helpers ═════════════════════════

    address internal constant MULTICALL3 = 0xcA11bde05977b3631167028862bE2a173976CA11;
    bytes4 internal constant GET_ETH_BALANCE = bytes4(keccak256("getEthBalance(address)"));

    /// @dev Root ALL over one CHECK entry per check; timing fields are not used by the evaluator.
    function _finish(JobSpec memory s) private view {
        uint256 n = s.checks.length;
        s.logic = new Logic[](n + 1);
        uint8[] memory children = new uint8[](n);
        for (uint256 i; i < n; ++i) {
            children[i] = uint8(i + 1);
            s.logic[i + 1] = Logic({kind: LogicKind.CHECK, check: uint8(i), children: new uint8[](0), k: 0});
        }
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        s.allowedMutability = AllowedMutability.NONE;
        s.executeBy = uint64(block.timestamp + 1 hours);
        s.failFinalAt = uint64(block.timestamp + 2 hours);
    }

    function _read(string memory chainId, address target, bytes4 selector, address account, ReadAt at, uint16 conf)
        private
        pure
        returns (Read memory r)
    {
        r.chainNamespace = NS;
        r.chainId = chainId;
        r.minConfirmations = conf;
        r.target = target;
        r.selector = selector;
        r.args = abi.encode(account);
        r.outputs = abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
        r.field = new uint8[](1);
        r.at = at;
    }

    function _num(uint8[] memory l, uint8[] memory r, Operation op, uint256 target)
        private
        pure
        returns (Check memory)
    {
        return Check({left: l, right: r, evaluation: Evaluation.NUMBER, operation: op, target: int256(target)});
    }

    function _cmp(uint8[] memory l, Operation op, uint256 target) private pure returns (Check memory) {
        return Check({
            left: l, right: new uint8[](0), evaluation: Evaluation.COMPARE, operation: op, target: int256(target)
        });
    }

    function _i(uint8 a) private pure returns (uint8[] memory x) {
        x = new uint8[](1);
        x[0] = a;
    }

    function _i(uint8 a, uint8 b) private pure returns (uint8[] memory x) {
        x = new uint8[](2);
        (x[0], x[1]) = (a, b);
    }
}
