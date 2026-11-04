// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Recurrence, RECURRING_JOB_PREFIX} from "./JobSpecTypes.sol";

/// @title JobDescription — reads a job's description, one-off or recurring
/// @notice - One-off: `abi.encode(JobSpec)`.
///         - Recurring: `RECURRING_JOB_PREFIX ‖ abi.encode(JobSpec, Recurrence)`. Without the prefix, the rest still
///           decodes as a `JobSpec`, since `Recurrence` is static and sits in the head after the spec's offset.
library JobDescription {
    /// @dev Prefix, the spec's offset word, then the five `Recurrence` words.
    uint256 internal constant RECURRING_HEAD = 4 + 32 * 6;
    /// @dev Byte offset of `Recurrence.index` in a recurring description.
    uint256 internal constant INDEX_AT = 4 + 32 * 4;

    /// @notice Whether `d` starts with the recurring-job prefix.
    function isRecurring(bytes memory d) internal pure returns (bool) {
        return d.length >= 4 && bytes4(d) == RECURRING_JOB_PREFIX;
    }

    /// @notice The bytes that decode as the `JobSpec`: `d` itself, or a copy without the prefix. `d` is not changed.
    function specBytes(bytes memory d) internal pure returns (bytes memory s) {
        if (!isRecurring(d)) return d;
        uint256 len = d.length - 4;
        s = new bytes(len);
        assembly ("memory-safe") {
            let from := add(d, 36)
            let to := add(s, 32)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(to, i), mload(add(from, i))) }
        }
    }

    /// @notice The `Recurrence` of a recurring description. Reverts unless `d` is `prefix ‖ abi.encode(JobSpec,
    ///         Recurrence)`'s head: the spec's offset must be 0xC0, past the five `Recurrence` words.
    function recurrence(bytes memory d) internal pure returns (Recurrence memory r) {
        require(isRecurring(d) && d.length >= RECURRING_HEAD, "not a recurring description");
        uint256 specOffset;
        uint256 start;
        uint256 period;
        uint256 count;
        uint256 index;
        uint256 fee;
        assembly ("memory-safe") {
            specOffset := mload(add(d, 36))
            let p := add(d, 68) // past the length word, the prefix and the spec's offset
            start := mload(p)
            period := mload(add(p, 32))
            count := mload(add(p, 64))
            index := mload(add(p, 96))
            fee := mload(add(p, 128))
        }
        require(
            specOffset == 0xc0 && start <= type(uint64).max && period <= type(uint32).max && count <= type(uint16).max
                && index <= type(uint16).max,
            "bad recurrence"
        );
        // forge-lint: disable-next-line(unsafe-typecast)
        r = Recurrence(uint64(start), uint32(period), uint16(count), uint16(index), fee); // safe: bounded above
    }

    /// @notice Sets `Recurrence.index` in a recurring description, in place.
    function setIndex(bytes memory d, uint16 index) internal pure {
        require(isRecurring(d) && d.length >= RECURRING_HEAD, "not a recurring description");
        assembly ("memory-safe") {
            mstore(add(add(d, 32), INDEX_AT), index)
        }
    }
}
