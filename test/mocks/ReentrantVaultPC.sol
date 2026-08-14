// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IRescuable {
    function rescueNativePC(address payable recipient, uint256 amount) external;
    function totalWithdrawable() external view returns (uint256);
    function totalEscrowed() external view returns (uint256);
}

/// @dev Vault that re-enters `rescueNativePC` while receiving the protocol fee.
///      `rescueNativePC` is not `nonReentrant`, so this is reachable. It exists to
///      prove the escrow-before-push ordering in `requestExternalReadSelf`: if the
///      escrow increment came after the fee push, the not-yet-escrowed callback
///      budget would look unattributed and be sweepable here.
contract ReentrantVaultPC {
    IRescuable public callback;
    address public sink;
    uint256 public swept;
    bool public attempted;

    function arm(address callback_, address sink_) external {
        callback = IRescuable(callback_);
        sink = sink_;
    }

    receive() external payable {
        if (address(callback) == address(0) || attempted) return;
        attempted = true;

        // The fee has already left the contract by the time this runs, so the
        // remaining balance is exactly the callback budget. If escrow was
        // incremented first it is fully attributed and nothing is takeable; if the
        // push came first the budget looks unattributed and is stealable.
        uint256 unattributed = address(callback).balance - callback.totalEscrowed();
        if (unattributed == 0) return;

        swept = unattributed;
        callback.rescueNativePC(payable(sink), unattributed);
    }
}
