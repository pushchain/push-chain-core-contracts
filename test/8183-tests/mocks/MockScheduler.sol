// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalScheduler} from "../../../src/agentic-commerce-8183/interfaces/IUniversalScheduler.sol";

/// @notice Stands in for Push's scheduler: records bookings; the test runs them, as the chain module would.
contract MockScheduler is IUniversalScheduler {
    struct Booking {
        address target;
        bytes data;
        uint64 executeAt;
        bool done;
    }

    Booking[] public bookings;
    /// @notice When set, `schedule` reverts.
    bool public broken;

    function setBroken(bool broken_) external {
        broken = broken_;
    }

    function schedule(address target, bytes calldata data, uint64 executeAt) external returns (uint256 id) {
        require(!broken, "scheduler down");
        id = bookings.length;
        bookings.push(Booking(target, data, executeAt, false));
    }

    function count() external view returns (uint256) {
        return bookings.length;
    }

    function booking(uint256 id) external view returns (Booking memory) {
        return bookings[id];
    }

    /// @notice Runs booking `id` once it is due. Returns whether the call succeeded.
    function run(uint256 id) external returns (bool ok) {
        Booking storage b = bookings[id];
        require(!b.done, "already run");
        require(block.timestamp >= b.executeAt, "not due");
        b.done = true;
        (ok,) = b.target.call(b.data);
    }

    /// @notice Calls `target` with `data` as the scheduler, ignoring bookings: for duplicate or early calls.
    function call(address target, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = target.call(data);
    }
}
