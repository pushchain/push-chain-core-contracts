// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalCallback} from "../../interfaces/IUniversalCallback.sol";
import {ReadSpec} from "../../libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../libraries/Types.sol";
import {
    Read,
    T_UINT,
    T_INT,
    T_BOOL,
    T_ADDRESS,
    T_BYTES,
    T_STRING,
    T_TUPLE,
    T_ARRAY,
    T_FIXED_ARRAY
} from "../libraries/JobSpecTypes.sol";
import {IUniversalCoreHeights, MAX_RESULT_LENGTH} from "./EvaluationTypes.sol";
import {EvmReadErrors} from "../libraries/Errors.sol";

/// @notice Mirror of the node's `EvmBlockRef`. `refType` 0 (AT_NUMBER) is the only value.
struct EvmBlockRef {
    uint8 refType;
    uint64 blockNumber;
}

/// @notice Mirror of the node's `EvmQueryEnvelope` (`universalClient/externalchains/evm/read_envelope.go`).
struct EvmQueryEnvelope {
    uint8 queryType;
    EvmBlockRef blockRef;
    bytes payload;
}

/// @notice Everything about one request that is not in the `Read`.
struct FireParams {
    address owner; // goes into `account.owner`; validators ignore it for EVM reads, it only has to be non-empty
    uint64 height; // the destination block the call runs at
    uint256 value; // protocol fee + callback budget, from `price`
    uint64 ttl; // Push blocks until the request may be expired
    address revertRecipient; // receives the unspent callback budget
    bytes4 callbackSelector;
    uint64 callbackGasLimit;
}

/// @title EvmReadLib — one EVM contract call through Read State: its block, its price, the request, the answer
/// @notice Internal functions, compiled into the UniversalEvaluator.
/// @dev Request:
///      - The query is `abi.encode(EvmQueryEnvelope)`: one dynamic tuple, as the node unpacks it. Payload for a
///        contract call is `abi.encode(target, callData)`, with `callData = selector ‖ args`.
///      - The callback must be prepaid. The node delivers an answer only when
///        `callbackBudget >= callbackGasLimit × base fee` (`x/ucallback/keeper/evm.go`, `CanAffordCallback`);
///        otherwise the read waits until it expires. `price` adds that budget, times a safety multiplier for a
///        base fee that rises before delivery. The unspent part is refunded to `revertRecipient`.
///      Answer:
///      - `decode` follows the V2 design line by line (test copy: `test/8183-tests/helpers/V2Decoder.sol`), with
///        two changes:
///          · a `field` that stops on a struct or a fixed array is not a value, so it returns not-ok instead of the
///            raw first word (`isValidShape` already refuses such a path);
///          · an array's length only counts if the heads of that many elements are present in the answer, so a
///            forged length word can't produce a value (the V2 decoder returned any length, even one that wraps
///            negative as an int256).
///      - `isValidShape`, run when the spec is frozen, bounds `outputs` and `field`, so `decode` does bounded work
///        on any answer.
///      - Bounded extraction, not full ABI validation: it follows offsets inside the answer and checks the value
///        fits its type code (uint ≤ int256 max, bool 0/1, address 160 bits), but it does not require canonical
///        offsets and does not know narrower widths (`uint8`, `bytes4`): the type codes don't carry them.
///      - The evaluator runs `decode` through a gas-capped external self-call inside `try`, so even a decoder bug
///        becomes "can't tell" instead of a reverted callback.
library EvmReadLib {
    uint8 internal constant QUERY_CONTRACT_CALL = 1;
    uint8 internal constant BLOCK_AT_NUMBER = 0;
    /// @notice The CAIP-2 namespace whose queries `fire` encodes (`EvmQueryEnvelope`): EVM chains.
    bytes32 internal constant EVM_NAMESPACE_HASH = keccak256("eip155");

    /// @notice The CAIP-2 key UniversalCore and Read State use for a read's chain.
    function chainKey(Read memory r) internal pure returns (string memory) {
        return string.concat(r.chainNamespace, ":", r.chainId);
    }

    /// @notice Push's tracked height for the read's chain.
    /// @dev Reverts if the chain is untracked, or, when `maxAge != 0`, if the height is older than `maxAge` seconds.
    function latestHeight(IUniversalCoreHeights core, Read memory r, uint256 maxAge)
        internal
        view
        returns (uint64)
    {
        string memory key = chainKey(r);
        uint256 h = core.chainHeightByChainNamespace(key);
        if (h == 0 || h > type(uint64).max) revert EvmReadErrors.ChainNotTracked(key);
        if (maxAge != 0) {
            uint256 seen = core.timestampObservedAtByChainNamespace(key);
            if (block.timestamp > seen + maxAge) revert EvmReadErrors.HeightStale(key, seen);
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(h); // safe: `h > type(uint64).max` reverts above
    }

    /// @notice What one request costs: the protocol fee plus a callback budget the node will accept.
    function price(IUniversalCallback cb, Read memory r, uint64 callbackGasLimit, uint256 budgetMultiplier)
        internal
        view
        returns (uint256)
    {
        return cb.estimateFee(r.chainNamespace, r.chainId) + uint256(callbackGasLimit) * block.basefee * budgetMultiplier;
    }

    /// @notice Sends one request and returns its id.
    function fire(IUniversalCallback cb, Read memory r, FireParams memory p) internal returns (uint256) {
        bytes memory payload = abi.encode(r.target, abi.encodePacked(r.selector, r.args));
        EvmQueryEnvelope memory env = EvmQueryEnvelope({
            queryType: QUERY_CONTRACT_CALL,
            blockRef: EvmBlockRef({refType: BLOCK_AT_NUMBER, blockNumber: p.height}),
            payload: payload
        });
        ReadSpec memory spec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: r.chainNamespace,
                chainId: r.chainId,
                owner: abi.encode(p.owner)
            }),
            query: abi.encode(env),
            minConfirmations: r.minConfirmations,
            blockNumber: p.height,
            expiryPushChainHeight: uint64(block.number) + p.ttl,
            maxFee: p.value,
            revertRecipient: p.revertRecipient
        });
        return cb.requestExternalReadSelf{value: p.value}(spec, p.callbackSelector, p.callbackGasLimit);
    }

    // ───────────────────────────── the answer ─────────────────────────────
    // forge-lint: disable-start(unsafe-typecast)
    /// @notice Longest `outputs` accepted.
    uint256 internal constant MAX_OUTPUTS_LENGTH = 128;
    /// @notice Most levels `field` may descend.
    uint256 internal constant MAX_FIELD_DEPTH = 8;
    /// @notice Deepest nesting `outputs` may describe.
    uint256 internal constant MAX_TYPE_DEPTH = 8;

    /// @notice The number to compare, from answer `res`.
    /// @return ok    Whether a value was found and it fits its type.
    /// @return value The number: integers as is, bool as 0/1, address as its number, bytesN raw,
    ///               bytes and string as their keccak256, arrays as their length.
    function decode(bytes memory outputs, uint8[] memory field, bytes calldata res)
        internal
        pure
        returns (bool ok, int256 value)
    {
        uint8 leaf;
        uint256 at;
        uint256 t;
        (ok, leaf, at, t) = _locate(outputs, field, res);
        if (!ok) return (false, 0);
        if (leaf == T_TUPLE || leaf == T_FIXED_ARRAY) return (false, 0);

        if (leaf == T_BYTES || leaf == T_STRING || leaf == T_ARRAY) {
            (bool ok2, uint256 len) = _word(res, at);
            if (!ok2) return (false, 0);
            if (leaf == T_ARRAY) {
                // The element heads (a pointer each if the element is dynamic) follow the length word and must all
                // be present. `_word` succeeded, so `at + 32 <= res.length`.
                uint256 elemBytes = 32 * _headWords(outputs, t + 1);
                if (len > (res.length - at - 32) / elemBytes) return (false, 0);
                return (true, int256(len)); // safe: len <= res.length / 32, far below int256 max
            }
            if (len > res.length || at + 32 + len > res.length) return (false, 0);
            return (true, int256(uint256(keccak256(res[at + 32:at + 32 + len]))));
        }

        (bool ok3, uint256 w) = _word(res, at);
        if (!ok3) return (false, 0);
        if (leaf == T_UINT) return w > uint256(type(int256).max) ? (false, int256(0)) : (true, int256(w));
        if (leaf == T_INT) return (true, int256(w));
        if (leaf == T_BOOL) return w > 1 ? (false, int256(0)) : (true, int256(w));
        if (leaf == T_ADDRESS) return w >> 160 != 0 ? (false, int256(0)) : (true, int256(w));
        return (true, int256(w)); // T_BYTESN: raw, for EQ / NEQ
    }

    // ───────────────────────────── shape check ─────────────────────────────

    /// @notice Whether `outputs` is a well-formed return-type list and `field` names one value in it.
    /// @dev - `outputs` is exactly one TUPLE (the return list), with no trailing bytes.
    ///      - Every code is known; TUPLE and FIXED_ARRAY have at least one member.
    ///      - `field` indexes are inside every TUPLE and FIXED_ARRAY it passes; ARRAY indexes are checked
    ///        against the answer at decode time.
    ///      - The value `field` lands on is not a TUPLE or FIXED_ARRAY.
    ///      - The return list's fixed part (its head) fits `MAX_RESULT_LENGTH`, so any answer of this shape fits
    ///        unless its variable-length data (bytes, string, arrays) is what makes it longer.
    function isValidShape(bytes memory outputs, uint8[] memory field) internal pure returns (bool) {
        if (outputs.length < 3 || outputs.length > MAX_OUTPUTS_LENGTH) return false;
        if (field.length == 0 || field.length > MAX_FIELD_DEPTH) return false;
        if (uint8(outputs[0]) != T_TUPLE) return false;
        (bool ok, uint256 end) = _wellFormed(outputs, 0, 0);
        if (!ok || end != outputs.length) return false;

        uint256 head;
        uint256 member = 2;
        for (uint256 j; j < uint8(outputs[1]); ++j) {
            head += _headWords(outputs, member);
            member = _skip(outputs, member);
        }
        if (head * 32 > MAX_RESULT_LENGTH) return false;

        uint256 t;
        for (uint256 i; i < field.length; ++i) {
            uint8 code = uint8(outputs[t]);
            uint256 idx = field[i];
            if (code == T_TUPLE) {
                if (idx >= uint8(outputs[t + 1])) return false;
                uint256 c = t + 2;
                for (uint256 j; j < idx; ++j) {
                    c = _skip(outputs, c);
                }
                t = c;
            } else if (code == T_ARRAY) {
                t = t + 1;
            } else if (code == T_FIXED_ARRAY) {
                if (idx >= uint8(outputs[t + 1])) return false;
                t = t + 2;
            } else {
                return false; // can't go inside a basic value
            }
        }
        uint8 leaf = uint8(outputs[t]);
        return leaf != T_TUPLE && leaf != T_FIXED_ARRAY;
    }

    /// @dev One type starting at `t` is complete and known; returns where it ends.
    function _wellFormed(bytes memory types, uint256 t, uint256 depth) private pure returns (bool, uint256) {
        if (depth > MAX_TYPE_DEPTH || t >= types.length) return (false, 0);
        uint8 code = uint8(types[t]);
        if (code >= T_UINT && code <= T_STRING) return (true, t + 1);
        if (code == T_ARRAY) return _wellFormed(types, t + 1, depth + 1);
        if (code != T_TUPLE && code != T_FIXED_ARRAY) return (false, 0);
        if (t + 1 >= types.length) return (false, 0);
        uint256 n = uint8(types[t + 1]);
        if (n == 0) return (false, 0);
        if (code == T_FIXED_ARRAY) return _wellFormed(types, t + 2, depth + 1);
        uint256 c = t + 2;
        for (uint256 j; j < n; ++j) {
            bool ok;
            (ok, c) = _wellFormed(types, c, depth + 1);
            if (!ok) return (false, 0);
        }
        return (true, c);
    }

    // ───────────────────────────── the V2 walker ─────────────────────────────

    /// @dev Walks the return types along `field` and finds where that value sits in `res`.
    /// @return ok   Whether the path resolves inside `res`.
    /// @return leaf The type code of the value found.
    /// @return at   Where its encoding (or its length word) starts in `res`.
    /// @return t    Where its type starts in `types`.
    function _locate(bytes memory types, uint8[] memory field, bytes calldata res)
        private
        pure
        returns (bool ok, uint8 leaf, uint256 at, uint256 t)
    {
        uint256 base; // where the current value's encoding starts in `res`; `t` is the position in `types`
        for (uint256 i; i < field.length; ++i) {
            uint8 code = uint8(types[t]);
            uint256 idx = field[i];
            uint256 elem;
            uint256 ptr;

            if (code == T_TUPLE) {
                if (idx >= uint8(types[t + 1])) return (false, 0, 0, 0);
                uint256 c = t + 2;
                uint256 head;
                for (uint256 j; j < idx; ++j) {
                    head += _headWords(types, c);
                    c = _skip(types, c);
                }
                uint256 slot = base + 32 * head;
                if (_isDynamic(types, c)) {
                    (ok, ptr) = _word(res, slot);
                    if (!ok || ptr > res.length) return (false, 0, 0, 0);
                    base += ptr;
                } else {
                    base = slot;
                }
                t = c;
            } else if (code == T_ARRAY) {
                elem = t + 1;
                uint256 len;
                (ok, len) = _word(res, base);
                if (!ok || idx >= len) return (false, 0, 0, 0);
                uint256 start = base + 32;
                if (_isDynamic(types, elem)) {
                    (ok, ptr) = _word(res, start + 32 * idx);
                    if (!ok || ptr > res.length) return (false, 0, 0, 0);
                    base = start + ptr;
                } else {
                    base = start + 32 * idx * _headWords(types, elem);
                }
                t = elem;
            } else if (code == T_FIXED_ARRAY) {
                if (idx >= uint8(types[t + 1])) return (false, 0, 0, 0);
                elem = t + 2;
                if (_isDynamic(types, elem)) {
                    (ok, ptr) = _word(res, base + 32 * idx);
                    if (!ok || ptr > res.length) return (false, 0, 0, 0);
                    base += ptr;
                } else {
                    base += 32 * idx * _headWords(types, elem);
                }
                t = elem;
            } else {
                return (false, 0, 0, 0); // can't go inside a basic value
            }
        }
        return (true, uint8(types[t]), base, t);
    }

    /// @dev bytes, string and T[] are dynamic; a struct or T[k] is dynamic if anything inside is.
    function _isDynamic(bytes memory types, uint256 t) private pure returns (bool) {
        uint8 code = uint8(types[t]);
        if (code == T_BYTES || code == T_STRING || code == T_ARRAY) return true;
        if (code == T_FIXED_ARRAY) return _isDynamic(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                if (_isDynamic(types, c)) return true;
                c = _skip(types, c);
            }
        }
        return false;
    }

    /// @dev Slots a value takes in its parent's head: 1 if dynamic (a pointer), else its full size.
    function _headWords(bytes memory types, uint256 t) private pure returns (uint256 n) {
        if (_isDynamic(types, t)) return 1;
        uint8 code = uint8(types[t]);
        if (code == T_FIXED_ARRAY) return uint8(types[t + 1]) * _headWords(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                n += _headWords(types, c);
                c = _skip(types, c);
            }
            return n;
        }
        return 1;
    }

    /// @dev The position in `types` right after the type starting at `t`.
    function _skip(bytes memory types, uint256 t) private pure returns (uint256) {
        uint8 code = uint8(types[t]);
        if (code == T_ARRAY) return _skip(types, t + 1);
        if (code == T_FIXED_ARRAY) return _skip(types, t + 2);
        if (code == T_TUPLE) {
            uint256 c = t + 2;
            for (uint256 j; j < uint8(types[t + 1]); ++j) {
                c = _skip(types, c);
            }
            return c;
        }
        return t + 1;
    }

    /// @dev One 32-byte slot of the answer, or not-ok if the answer is too short.
    function _word(bytes calldata b, uint256 at) private pure returns (bool, uint256) {
        if (at > b.length || b.length - at < 32) return (false, 0);
        return (true, uint256(bytes32(b[at:at + 32])));
    }
    // forge-lint: disable-end(unsafe-typecast)
}
