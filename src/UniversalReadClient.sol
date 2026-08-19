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

    /// @dev    Defaults `revertRecipient` to this contract when unset. Refunds are
    ///         PUSHED there on settlement, so an inheriting contract that keeps the
    ///         default MUST declare a payable `receive()` -- otherwise the push is
    ///         rejected and the refund is forfeited. Point `revertRecipient` at an
    ///         EOA to avoid that entirely.
    function _requestRead(
        ReadSpec memory spec,
        bytes memory localState,
        uint64 callbackGasLimit
    ) internal returns (uint256 requestId) {
        if (spec.revertRecipient == address(0)) {
            spec.revertRecipient = address(this);
        }
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

    function universalCallback() external view returns (IUniversalCallback) {
        return UNIVERSAL_CALLBACK;
    }

    function getLocalContext(uint256 requestId) external view returns (bytes memory) {
        return _localContext[requestId];
    }
}
