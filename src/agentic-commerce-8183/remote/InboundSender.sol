// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title InboundSender — the sender of one EvaluationGateway inbound
/// @notice The gateway deploys one per job message with CREATE2 (salt `RemoteKeys.senderSalt(kernel, jobId, slot)`)
///         and sends that message's inbound through it, so Push gives every message its own UEA.
/// @dev A UEA runs a payload only if its nonce is the UEA's current nonce, and a payload that fails on Push leaves the
///      nonce where it was. A sender used for one message only always sends nonce 0: the message can be sent again
///      until it runs once, and a copy after that fails on Push. A sender shared by many jobs would need the next
///      nonce, which the remote chain can't know.
///      Only the gateway that deployed it can send through it, and the gateway encodes the `sendUniversalTx` call, so
///      the sender stays small (it is deployed once per message). It holds nothing: `UniversalGateway` takes the whole
///      `msg.value` and refunds nothing to its caller.
contract InboundSender {
    error NotGateway(address caller);

    address private immutable GATEWAY;

    constructor() {
        GATEWAY = msg.sender;
    }

    /// @notice Calls `target` with `data` and `msg.value`, as this contract; bubbles up a revert.
    function send(address target, bytes calldata data) external payable {
        if (msg.sender != GATEWAY) revert NotGateway(msg.sender);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)
            if iszero(call(gas(), target, callvalue(), ptr, data.length, 0, 0)) {
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
