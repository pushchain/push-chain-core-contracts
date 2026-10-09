// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice The few views the evaluator reads on other teams' contracts that their own interfaces don't declare.

/// @title IAGWCheckpoints
/// @notice Mirror of the AGW's owner-side checkpoint counter.
/// @dev - Source: `push-agentic-wallets`, branch `pushAgenticWallet_v3` (`e704d5b`), `src/AGW.sol`
///        (`checkpointCount`, `lastCheckpointBlock`) and `docs/1_AGW.md` §4.5.
///      - Every owner-door call, rules grant and rules revoke advances the count, before the call runs; agent
///        actions never do. A job records the count at `fund`; a later count that differs means the owner side
///        touched the wallet during the job.
interface IAGWCheckpoints {
    function checkpointCount() external view returns (uint64);
}

/// @title IUniversalCoreHeights
/// @notice The two UniversalCore views the evaluator reads: Push's tracked height for a chain, and when it was last
///         updated.
/// @dev - Source: `src/UniversalCore.sol` (`chainHeightByChainNamespace`, `timestampObservedAtByChainNamespace`),
///        both written by `setChainMeta`. Keyed by the CAIP-2 string, e.g. `"eip155:8453"`.
///      - UniversalCore's own staleness setting guards gas data only, so callers check freshness themselves.
interface IUniversalCoreHeights {
    function chainHeightByChainNamespace(string memory chainNamespace) external view returns (uint256);

    function timestampObservedAtByChainNamespace(string memory chainNamespace) external view returns (uint256);
}

/// @title IReadStateDomains
/// @notice The one UniversalCallback view the evaluator reads that `IUniversalCallback` does not declare.
/// @dev Source: `src/UniversalCallback.sol` (`isDomainBlocked`), set by its admin with `updateBlockedDomain`. A blocked
///      domain makes `requestExternalReadSelf` revert `DomainBlocked`.
interface IReadStateDomains {
    function isDomainBlocked(string calldata chainNamespace, string calldata chainId) external view returns (bool);
}
