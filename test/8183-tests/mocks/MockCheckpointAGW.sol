// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice A stand-in for the AGW's owner side, with its checkpoint counter.
/// @dev - `execute` mirrors the real owner door's rule that matters here: the counter ticks BEFORE each call
///        (`AGW.sol`, `_checkpointOwnerCall`), so a hook reading it during `fund` sees the funding call's tick.
///      - Only the owner may call. No policy, no modules: that is the real owner door too.
contract MockCheckpointAGW {
    address public immutable owner;
    uint64 internal _count;
    /// @notice When set, `checkpointCount` reverts, as a wallet without the counter would.
    bool public counterBroken;

    constructor(address owner_) {
        owner = owner_;
    }

    function checkpointCount() external view returns (uint64) {
        require(!counterBroken, "no counter");
        return _count;
    }

    function setCounterBroken(bool broken) external {
        counterBroken = broken;
    }

    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        require(msg.sender == owner, "not owner");
        unchecked {
            ++_count;
        }
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    receive() external payable {}
}
