// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalScheduler} from "./interfaces/IUniversalScheduler.sol";

/// @title UniversalScheduler — Push's minimal call scheduler
/// @notice Allowed bookers (the UniversalHook) book calls; Push's scheduler module runs each one once it is due.
/// @dev - No fee: only bookers the admin allows may book.
///      - `execute` never reverts for a due booking: the target's failure is recorded, so the module's call succeeds.
///      - Each booking runs at most once; the target is expected to ignore stale calls.
contract UniversalScheduler is IUniversalScheduler {
    struct Booking {
        address target;
        uint64 executeAt;
        bool done;
        address booker;
        bytes data;
    }

    /// @notice The chain module's address: the only caller of `execute`.
    address public immutable MODULE;
    /// @notice May change the bookers.
    address public admin;
    /// @notice Who may book.
    mapping(address => bool) public isBooker;

    Booking[] internal _bookings;

    event Scheduled(uint256 indexed id, address indexed booker, address target, uint64 executeAt, bytes data);
    event Executed(uint256 indexed id, bool ok, bytes result);
    event BookerSet(address indexed booker, bool allowed);
    event AdminSet(address admin);

    error CallerIsNotAdmin(address caller);
    error CallerIsNotBooker(address caller);
    error CallerIsNotModule(address caller);
    error UnknownBooking(uint256 id);
    error AlreadyExecuted(uint256 id);
    error NotDue(uint256 id, uint64 executeAt);
    error ZeroAddress();

    constructor(address module_, address admin_) {
        if (module_ == address(0) || admin_ == address(0)) revert ZeroAddress();
        MODULE = module_;
        admin = admin_;
        emit AdminSet(admin_);
    }

    /// @inheritdoc IUniversalScheduler
    function schedule(address target, bytes calldata data, uint64 executeAt) external returns (uint256 id) {
        if (!isBooker[msg.sender]) revert CallerIsNotBooker(msg.sender);
        if (target == address(0)) revert ZeroAddress();
        id = _bookings.length;
        _bookings.push(Booking({target: target, executeAt: executeAt, done: false, booker: msg.sender, data: data}));
        emit Scheduled(id, msg.sender, target, executeAt, data);
    }

    /// @notice Runs booking `id`. The module only, once it is due, once.
    function execute(uint256 id) external returns (bool ok, bytes memory result) {
        if (msg.sender != MODULE) revert CallerIsNotModule(msg.sender);
        if (id >= _bookings.length) revert UnknownBooking(id);
        Booking storage b = _bookings[id];
        if (b.done) revert AlreadyExecuted(id);
        if (block.timestamp < b.executeAt) revert NotDue(id, b.executeAt);
        b.done = true;
        (ok, result) = b.target.call(b.data);
        emit Executed(id, ok, result);
    }

    /// @notice Up to `max` ids from `fromId` on that are due and not yet run, for the module to execute.
    function due(uint256 fromId, uint256 max) external view returns (uint256[] memory ids) {
        ids = new uint256[](max);
        uint256 n;
        for (uint256 id = fromId; id < _bookings.length && n < max; ++id) {
            Booking storage b = _bookings[id];
            if (!b.done && b.executeAt <= block.timestamp) ids[n++] = id;
        }
        assembly ("memory-safe") {
            mstore(ids, n)
        }
    }

    function booking(uint256 id) external view returns (Booking memory) {
        if (id >= _bookings.length) revert UnknownBooking(id);
        return _bookings[id];
    }

    function bookingCount() external view returns (uint256) {
        return _bookings.length;
    }

    function setBooker(address booker, bool allowed) external {
        if (msg.sender != admin) revert CallerIsNotAdmin(msg.sender);
        isBooker[booker] = allowed;
        emit BookerSet(booker, allowed);
    }

    function setAdmin(address admin_) external {
        if (msg.sender != admin) revert CallerIsNotAdmin(msg.sender);
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
        emit AdminSet(admin_);
    }
}
