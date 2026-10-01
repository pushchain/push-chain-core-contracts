// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    Fill,
    FillSource,
    ReadTemplate,
    TargetSource,
    CheckTemplate
} from "../../../src/agentic-commerce-8183/libraries/JobSpecBuilder.sol";
import {
    EvalType,
    Op,
    NodeKind,
    Node,
    T_UINT,
    T_ADDRESS,
    T_TUPLE
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

/// @title TemplateParts — TEST ONLY: chain-agnostic builders for evaluation templates
/// @notice Shared by the evaluation, conformance and marketplace suites. Every builder is pure.
abstract contract TemplateParts {
    bytes4 internal constant BALANCE_OF = bytes4(keccak256("balanceOf(address)"));
    bytes4 internal constant GET_RESERVE_DATA = bytes4(keccak256("getReserveData(address)"));
    bytes4 internal constant MAX_WITHDRAW = bytes4(keccak256("maxWithdraw(address)"));

    // ───────── outputs and fields ─────────

    function _uintOut() internal pure returns (bytes memory) {
        return abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
    }

    /// @dev Aave v3 `getReserveData` → one 15-field struct, the V2 doc's encoding.
    function _reserveDataOut() internal pure returns (bytes memory) {
        return abi.encodePacked(
            abi.encodePacked(T_TUPLE, uint8(1), T_TUPLE, uint8(15), T_TUPLE, uint8(1), T_UINT),
            abi.encodePacked(T_UINT, T_UINT, T_UINT, T_UINT, T_UINT, T_UINT, T_UINT),
            abi.encodePacked(T_ADDRESS, T_ADDRESS, T_ADDRESS, T_ADDRESS, T_UINT, T_UINT, T_UINT)
        );
    }

    function _f(uint8 a) internal pure returns (uint8[] memory f) {
        f = new uint8[](1);
        f[0] = a;
    }

    function _f2(uint8 a, uint8 b) internal pure returns (uint8[] memory f) {
        f = new uint8[](2);
        f[0] = a;
        f[1] = b;
    }

    function _noFills() internal pure returns (Fill[] memory) {
        return new Fill[](0);
    }

    function _ceaFill(uint8 word) internal pure returns (Fill[] memory fills) {
        fills = new Fill[](1);
        fills[0] = Fill({word: word, source: FillSource.CEA, param: 0});
    }

    // ───────── reads, checks, nodes ─────────

    function _read(
        string memory chainId,
        address target,
        bytes4 selector,
        bytes memory args,
        Fill[] memory fills,
        bytes memory outputs,
        uint8[] memory field
    ) internal pure returns (ReadTemplate memory) {
        return ReadTemplate({
            chainNamespace: "eip155",
            chainId: chainId,
            minConfirmations: 12,
            target: target,
            selector: selector,
            args: args,
            fills: fills,
            outputs: outputs,
            field: field
        });
    }

    /// @dev `token.balanceOf(CEA)` on `chainId`: args are one zero word the CEA fill overwrites.
    function _balanceOfCEA(string memory chainId, address token) internal pure returns (ReadTemplate memory) {
        return _read(chainId, token, BALANCE_OF, new bytes(32), _ceaFill(0), _uintOut(), _f(0));
    }

    function _chk(uint8 read, EvalType e, Op op, TargetSource src, int256 value)
        internal
        pure
        returns (CheckTemplate memory)
    {
        return CheckTemplate({read: read, evalType: e, op: op, source: src, value: value});
    }

    function _checkNode(uint8 check) internal pure returns (Node memory) {
        return Node({kind: NodeKind.CHECK, check: check, children: new uint8[](0), k: 0});
    }

    function _parent(NodeKind kind, uint8[] memory children, uint8 k) internal pure returns (Node memory) {
        return Node({kind: kind, check: 0, children: children, k: k});
    }

    function _kids(uint8 a, uint8 b) internal pure returns (uint8[] memory c) {
        c = new uint8[](2);
        c[0] = a;
        c[1] = b;
    }

    function _kids3(uint8 a, uint8 b, uint8 d) internal pure returns (uint8[] memory c) {
        c = new uint8[](3);
        c[0] = a;
        c[1] = b;
        c[2] = d;
    }
}
