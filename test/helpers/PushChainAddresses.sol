// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title PushChainAddresses
/// @notice Central address book for Push Chain Donut Testnet deployments.
///         Update this file when addresses change — all fork tests inherit from here.
/// @dev Source: pushchain/push-chain-swap-internal-amm-contracts test-addresses.json
///              and protocol official-prc20.json
abstract contract PushChainAddresses {
    // =========================================================================
    // Uniswap V3 Infrastructure — Push Chain Donut Testnet
    // =========================================================================

    address internal constant UNISWAP_FACTORY = 0x81b8Bca02580C7d6b636051FDb7baAC436bFb454;
    address internal constant UNISWAP_ROUTER = 0x5D548bB9E305AAe0d6dc6e6fdc3ab419f6aC0037;
    address internal constant UNISWAP_QUOTER = 0x83316275f7C2F79BC4E26f089333e88E89093037;
    address internal constant WPC_TOKEN = 0xE17DD2E0509f99E9ee9469Cf6634048Ec5a3ADe9;

    // =========================================================================
    // Protocol Constants
    // =========================================================================

    address internal constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    // =========================================================================
    // PRC20 Token Addresses — Push Chain Donut Testnet
    // =========================================================================

    address internal constant PSOL_TOKEN = 0x5D525Df2bD99a6e7ec58b76aF2fd95F39874EBed;
    address internal constant PETH_TOKEN = 0x2971824Db68229D087931155C2b8bB820B275809;
    address internal constant USDT_ETH_TOKEN = 0xCA0C5E6F002A389E1580F0DB7cd06e4549B5F9d3;
    address internal constant USDC_ETH_TOKEN = 0x387b9C8Db60E74999aAAC5A2b7825b400F12d68E;
    address internal constant PETH_ARB_TOKEN = 0xc0a821a1AfEd1322c5e15f1F4586C0B8cE65400e;
    address internal constant PBNB_TOKEN = 0x7a9082dA308f3fa005beA7dB0d203b3b86664E36;
    address internal constant USDT_BASE_TOKEN = 0x2C455189D2af6643B924A981a9080CcC63d5a567;

    // =========================================================================
    // Uniswap V3 Pool Addresses — Push Chain Donut Testnet
    // =========================================================================

    address internal constant PSOL_WPC_POOL = 0x0E5914e3A7e2e6d18330Dd33fA387Ce33Da48b54;
    address internal constant PETH_WPC_POOL = 0x012d5C099f8AE00009f40824317a18c3A342f622;
    address internal constant USDT_ETH_WPC_POOL = 0x2d46b2b92266f34345934F17039768cd631aB026;
    address internal constant USDC_ETH_WPC_POOL = 0x69B21660F49f2B8F60B0177Abc751a08EBEa0Ae3;
    address internal constant PETH_ARB_WPC_POOL = 0x1354c9A72F447f60F4811FC34b8C2e084FE338A3;
    address internal constant PBNB_WPC_POOL = 0x826edC20c926653f4ddC01b8d4C7Df31a403e7d6;
}
