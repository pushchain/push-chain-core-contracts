// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice The UniversalCore views Read State, the UniversalHook and the UniversalEvaluator read.
/// @dev Same keys as UniversalCore: heights and timestamps by CAIP-2 string, the read base fee by (namespace, id).
contract MockReadCore {
    mapping(string => uint256) public chainHeightByChainNamespace;
    mapping(string => uint256) public timestampObservedAtByChainNamespace;
    mapping(string => mapping(string => uint256)) public readBaseFeeByChainNamespace;

    /// @notice Sets a chain's tracked height, stamped now, as `setChainMeta` does.
    function setChainHeight(string memory chainKey, uint256 height) external {
        chainHeightByChainNamespace[chainKey] = height;
        timestampObservedAtByChainNamespace[chainKey] = block.timestamp;
    }

    function setObservedAt(string memory chainKey, uint256 ts) external {
        timestampObservedAtByChainNamespace[chainKey] = ts;
    }

    function setReadBaseFee(string memory chainNamespace, string memory chainId, uint256 fee) external {
        readBaseFeeByChainNamespace[chainNamespace][chainId] = fee;
    }
}
