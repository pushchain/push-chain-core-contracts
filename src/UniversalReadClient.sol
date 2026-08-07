// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalCallback} from "./interfaces/IUniversalCallback.sol";
import {IUniversalReadClient} from "./interfaces/IUniversalReadClient.sol";
import {ReadSpec} from "./libraries/ReadTypes.sol";
import {UniversalCallbackErrors} from "./libraries/Errors.sol";

abstract contract UniversalReadClient is IUniversalReadClient {
    IUniversalCallback internal immutable UNIVERSAL_CALLBACK;
    mapping(uint256 => bytes) private _localContext;

    constructor(address universalCallback_) {
        if (universalCallback_ == address(0)) {
            revert UniversalCallbackErrors.ZeroAddressInit();
        }
        UNIVERSAL_CALLBACK = IUniversalCallback(universalCallback_);
    }

    function _requestRead(
        ReadSpec memory spec,
        bytes memory localState,
        uint64 callbackGasLimit
    ) internal returns (uint256 requestId) {
        requestId = UNIVERSAL_CALLBACK.requestExternalReadSelf{value: msg.value}(
            spec, this.onUniversalData.selector, callbackGasLimit
        );
        _localContext[requestId] = localState;
    }

    function onUniversalData(
        uint256 requestId,
        bytes calldata resultData
    ) external {
        if (msg.sender != address(UNIVERSAL_CALLBACK)) {
            revert UniversalCallbackErrors.UnauthorizedCaller();
        }
        bytes memory localState = _localContext[requestId];
        delete _localContext[requestId];
        _onReadResult(requestId, resultData, localState);
    }

    function _onReadResult(
        uint256 requestId,
        bytes calldata resultData,
        bytes memory localState
    ) internal virtual;

    /// @notice         Claim any refunds credited to this contract by the callback.
    /// @dev            Returns 0 instead of reverting when nothing is owed, so it is
    ///                 safe to call unconditionally. The reclaimed PC arrives via
    ///                 this contract's `receive()`, which inheriting contracts MUST
    ///                 declare -- without one the transfer reverts and the refund
    ///                 stays unclaimable.
    /// @return amount  Amount reclaimed, or 0 when nothing was owed.
    function _withdrawRefunds() internal returns (uint256 amount) {
        amount = UNIVERSAL_CALLBACK.withdrawable(address(this));
        if (amount == 0) return 0;
        UNIVERSAL_CALLBACK.withdraw();
    }

    function universalCallback() external view returns (IUniversalCallback) {
        return UNIVERSAL_CALLBACK;
    }

    function getLocalContext(uint256 requestId) external view returns (bytes memory) {
        return _localContext[requestId];
    }
}
