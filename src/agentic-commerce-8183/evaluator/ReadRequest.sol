// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IUniversalCallback} from "../../interfaces/IUniversalCallback.sol";
import {ReadSpec} from "../../libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../libraries/Types.sol";
import {IUniversalCoreHeights} from "./ExternalInterfaces.sol";
import {Read} from "../libraries/JobSpecTypes.sol";
import {ReadRequestErrors} from "../libraries/Errors.sol";

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

/// @title ReadRequest — one Read State contract call at a pinned block
/// @dev - The query is `abi.encode(EvmQueryEnvelope)`: one dynamic tuple, as the node unpacks it. Payload for a
///        contract call is `abi.encode(target, callData)`, with `callData = selector ‖ args`.
///      - The callback must be prepaid. The node delivers an answer only when
///        `callbackBudget >= callbackGasLimit × base fee` (`x/ucallback/keeper/evm.go`, `CanAffordCallback`);
///        otherwise the read waits until it expires. `price` adds that budget, times a safety multiplier for a
///        base fee that rises before delivery. The unspent part is refunded to `revertRecipient`.
library ReadRequest {
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
        if (h == 0 || h > type(uint64).max) revert ReadRequestErrors.ChainNotTracked(key);
        if (maxAge != 0) {
            uint256 seen = core.timestampObservedAtByChainNamespace(key);
            if (block.timestamp > seen + maxAge) revert ReadRequestErrors.HeightStale(key, seen);
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
}
