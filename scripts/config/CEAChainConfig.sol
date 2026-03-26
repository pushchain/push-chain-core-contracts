// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  CEAChainConfig
/// @notice Base struct and resolver for per-chain CEA deployment parameters.
/// @dev    Add a new chain by:
///         1. Create a new file in scripts/config/ (e.g., MyChain.sol)
///         2. Inherit CEAChainConfig and override _chainId() + _loadConfig()
///         3. Register it in the if/else ladder in getConfig()

abstract contract CEAChainConfig {
    struct Config {
        address owner;
        address vault;
        address universalGateway;
        address ceaFactoryProxy; // Set to address(0) for fresh deploys
    }

    /// @notice Resolves the config for the current chain.
    /// @dev    Reverts if block.chainid is not supported.
    function getConfig()
        internal
        view
        returns (Config memory)
    {
        uint256 id = block.chainid;

        if (id == 97) return _bscTestnet();
        if (id == 421614) return _arbitrumSepolia();
        if (id == 11155111) return _ethSepolia();
        if (id == 84532) return _baseSepolia();

        revert("CEAChainConfig: unsupported chain");
    }

    // =====================================================================
    //  BSC Testnet (Chain ID: 97)
    // =====================================================================

    function _bscTestnet()
        private
        pure
        returns (Config memory)
    {
        return Config({
            owner: 0x6dD2cA20ec82E819541EB43e1925DbE46a441970,
            vault: 0xE52AC4f8DD3e0263bDF748F3390cdFA1f02be881,
            universalGateway: 0x44aFFC61983F4348DdddB886349eb992C061EaC0,
            ceaFactoryProxy: 0xe2182dae2dc11cBF6AA6c8B1a7f9c8315A6B0719
        });
    }

    // =====================================================================
    //  Arbitrum Sepolia (Chain ID: 421614)
    // =====================================================================

    function _arbitrumSepolia()
        private
        pure
        returns (Config memory)
    {
        return Config({
            owner: address(0),             // TODO: set before deploying
            vault: address(0),             // TODO: set before deploying
            universalGateway: address(0),  // TODO: set before deploying
            ceaFactoryProxy: address(0)    // Set after CEAFactory deploy
        });
    }

    // =====================================================================
    //  Ethereum Sepolia (Chain ID: 11155111)
    // =====================================================================

    function _ethSepolia()
        private
        pure
        returns (Config memory)
    {
        return Config({
            owner: address(0),             // TODO: set before deploying
            vault: address(0),             // TODO: set before deploying
            universalGateway: address(0),  // TODO: set before deploying
            ceaFactoryProxy: address(0)    // Set after CEAFactory deploy
        });
    }

    // =====================================================================
    //  Base Sepolia (Chain ID: 84532)
    // =====================================================================

    function _baseSepolia()
        private
        pure
        returns (Config memory)
    {
        return Config({
            owner: address(0),             // TODO: set before deploying
            vault: address(0),             // TODO: set before deploying
            universalGateway: address(0),  // TODO: set before deploying
            ceaFactoryProxy: address(0)    // Set after CEAFactory deploy
        });
    }
}
