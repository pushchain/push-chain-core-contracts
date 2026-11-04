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

    /// @notice The only caller of `executeRenewal` (the UniversalHook), set by the owner; zero = none.
    address public renewer;
    /// @notice When set, `executeRenewal` reverts, as a wallet without the renewal rule would.
    bool public renewalBroken;

    function setRenewer(address renewer_) external {
        require(msg.sender == owner, "not owner");
        renewer = renewer_;
    }

    function setRenewalBroken(bool broken) external {
        renewalBroken = broken;
    }

    /// @notice When set, `executeRenewal` returns this without calling: a wallet lying about what it did.
    bytes public forcedReturn;
    bool public forceReturn;

    function setForcedReturn(bool force, bytes calldata ret) external {
        forceReturn = force;
        forcedReturn = ret;
    }

    /// @notice The renewal door (`IAGWRenewal`): the hook's calls, no owner tick.
    function executeRenewal(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        require(msg.sender == renewer && renewer != address(0), "not renewer");
        require(!renewalBroken, "no renewal rule");
        if (forceReturn) return forcedReturn;
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
