// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev    Defines public-facing functions for UniversalCore contract.
interface IUniversalCore {
    // =========================
    //    UC: EVENTS
    // =========================

    event SetChainMeta(string chainNamespace, uint256 price, uint256 chainHeight, uint256 observedAt);
    event SetGasToken(string chainNamespace, address prc20);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event SetGasPCPool(string chainNamespace, address pool, uint24 fee);
    event DepositPRC20WithAutoSwap(
        address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address recipient
    );
    event SwapAndBurnGas(address indexed gasToken, uint256 pcIn, uint256 gasFee, uint24 fee, address indexed caller);
    event SetProtocolFeeByToken(address indexed token, uint256 fee);
    event SetBaseGasLimitByChain(string chainNamespace, uint256 gasLimit);
    event SetRescueFundsGasLimitByChain(string chainNamespace, uint256 gasLimit);
    event SetMaxStalenessByChain(string chainNamespace, uint256 maxStaleness);
    event SetL1GasFeeByChain(string chainNamespace, uint256 l1GasFee);
    event SetTssFundMigrationGasLimitByChain(string chainNamespace, uint256 gasLimit);
    event RefundUnusedGas(
        address indexed gasToken, uint256 amount, address indexed recipient, bool swapped, uint256 pcOut
    );

    event SetAutoSwapSupported(address indexed token, bool supported);
    event SetWPC(address indexed oldAddr, address indexed newAddr);
    event SetUniversalGatewayPC(address indexed oldAddr, address indexed newAddr);
    event SetUniswapV3Addresses(address factory, address swapRouter);
    event SetDefaultFeeTier(address indexed token, uint24 feeTier);

    /// @notice                  Emitted when stuck native PC is rescued by admin.
    /// @param to                Recipient of the rescued PC
    /// @param amount            Amount of native PC rescued
    event RescueNativePC(address indexed to, uint256 amount);

    // =========================
    //    UC_1: UE MODULE FUNCTIONS
    // =========================

    /// @notice             Deposits PRC20 tokens to the provided recipient address.
    /// @dev                Can only be called by the Universal Executor Module.
    ///                     For any inbound transactions of moving supported tokens
    ///                     from external chains to Push Chain, the Universal Executor
    ///                     Module uses this function to deposit the tokens to the
    ///                     recipient address. The recipient address can be any address
    ///                     of the user's choice.
    /// @param prc20        PRC20 address for deposit
    /// @param amount       Amount to deposit
    /// @param recipient    Address to deposit tokens to
    function depositPRC20Token(address prc20, uint256 amount, address recipient) external;

    /// @notice             Deposits PRC20 tokens and automatically swaps them to
    ///                     native PC before sending to recipient.
    /// @dev                Can only be called by the Universal Executor Module.
    ///                     Can only be called if the PRC20 token is in the auto-swap
    ///                     supported list (e.g. pETH, pSOL, pUSDC etc.).
    ///                     If no pool exists, reverts with appropriate error.
    ///                     Default values are used when parameters are set to 0.
    ///                     Recipient address always receives the swapped native PC tokens.
    /// @param prc20        PRC20 address for deposit and swap
    /// @param amount       Amount to deposit and swap
    /// @param recipient    Address to receive the swapped native PC tokens
    /// @param fee          Uniswap V3 fee tier for the pool (0 = use default)
    /// @param minPCOut     Minimum amount of native PC expected from the swap (must be > 0)
    /// @param deadline     Timestamp after which the transaction will revert (0 = use default)
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address recipient,
        uint24 fee,
        uint256 minPCOut,
        uint256 deadline
    ) external;

    /// @notice             Refund unused gas to recipient, optionally swapping PRC20 to WPC.
    /// @param gasToken     Gas token PRC20 address
    /// @param amount       Amount to refund
    /// @param recipient    Address to receive the refund
    /// @param withSwap     If true, swap PRC20 to WPC via Uniswap V3
    /// @param fee          Uniswap V3 fee tier (0 = use default; ignored if !withSwap)
    /// @param minPCOut     Minimum WPC out (must be > 0 if withSwap; ignored if !withSwap)
    function refundUnusedGas(
        address gasToken,
        uint256 amount,
        address recipient,
        bool withSwap,
        uint24 fee,
        uint256 minPCOut
    ) external;

    // =========================
    //    UC_2: GATEWAY FUNCTIONS
    // =========================

    /// @notice                 Swap native PC for gas token PRC20 and burn gasFee.
    /// @param gasToken         Gas token PRC20 address
    /// @param fee              Uniswap V3 fee tier (0 = use default)
    /// @param gasFee           Gas fee amount to burn
    /// @param deadline         Swap deadline (0 = use default)
    /// @param caller           Address to receive unused PC refund
    /// @return gasTokenOut     Total gas token swapped (gasFee)
    /// @return refund          Unused PC refunded to caller
    function swapAndBurnGas(address gasToken, uint24 fee, uint256 gasFee, uint256 deadline, address caller)
        external
        payable
        returns (uint256 gasTokenOut, uint256 refund);

    // =========================
    //    UC_3: PUBLIC GETTERS
    // =========================

    /// @notice                 Get gas token PRC20 address for a chain.
    /// @param chainNamespace   Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @return gasToken        Gas token address
    function gasTokenPRC20ByChainNamespace(string memory chainNamespace) external view returns (address gasToken);

    /// @notice                 Get gas price for a chain.
    /// @param chainNamespace   Chain Namespace
    /// @return price           Gas price
    function gasPriceByChainNamespace(string memory chainNamespace) external view returns (uint256 price);

    /// @notice                      Get base gas limit for a chain.
    /// @param chainNamespace        Chain Namespace
    /// @return baseGasLimit         Base gas limit for the chain
    function baseGasLimitByChainNamespace(string memory chainNamespace) external view returns (uint256 baseGasLimit);

    /// @notice                      Get rescue funds gas limit for a chain.
    /// @param chainNamespace        Chain Namespace
    /// @return rescueGasLimit       Rescue funds gas limit for the chain
    function rescueFundsGasLimitByChainNamespace(string memory chainNamespace)
        external
        view
        returns (uint256 rescueGasLimit);

    /// @notice                 Get gas fee for a PRC20 token, split into gasFee and protocolFee.
    /// @dev                    When gasLimitWithBaseLimit is 0, falls back to per-chain base gas limit.
    ///                         Reverts with GasLimitBelowBase when gasLimitWithBaseLimit is non-zero
    ///                         but below the chain's base gas limit.
    /// @param _prc20           PRC20 address
    /// @param gasLimitWithBaseLimit Gas limit (0 = use per-chain base gas limit)
    /// @return gasToken        Gas token address
    /// @return gasFee          Gas fee (gasPrice * effective gas limit)
    /// @return protocolFee     Protocol fee in native PC from protocolFeeByToken mapping
    /// @return gasPrice        Gas price on the external chain
    /// @return chainNamespace  Source chain namespace
    /// @return gasLimitUsed    Effective gas limit used to compute gasFee
    function getOutboundTxGasAndFees(address _prc20, uint256 gasLimitWithBaseLimit)
        external
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
            uint256 gasPrice,
            string memory chainNamespace,
            uint256 gasLimitUsed
        );

    /// @notice                 Get rescue funds gas limit, fee, and related config for a PRC20 token.
    /// @param _prc20           PRC20 address
    /// @return gasToken        Gas token address
    /// @return gasFee          Gas fee (gasPrice * rescueGasLimit)
    /// @return rescueGasLimit  Rescue funds gas limit for the chain
    /// @return gasPrice        Gas price on the external chain
    /// @return chainNamespace  Source chain namespace
    function getRescueFundsGasLimit(address _prc20)
        external
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 rescueGasLimit,
            uint256 gasPrice,
            string memory chainNamespace
        );

    /// @notice                 Get the protocol fee (in native PC) for a given token.
    /// @param token            Token address
    /// @return                 Protocol fee amount in native PC
    function protocolFeeByToken(address token) external view returns (uint256);

    /// @notice                 Set protocol fee (in native PC) for a token.
    /// @param token            Token address
    /// @param fee              Protocol fee amount in native PC
    function updateProtocolFeeByToken(address token, uint256 fee) external;

    /// @notice                  Set rescue funds gas limit for a specific chain.
    /// @param chainNamespace    Chain Namespace
    /// @param gasLimit          Rescue funds gas limit for the chain
    function updateRescueFundsGasLimitByChain(string memory chainNamespace, uint256 gasLimit) external;

    /// @notice                  Set L1 gas fee for a specific chain.
    /// @param chainNamespace    Chain Namespace
    /// @param l1GasFee          L1 gas fee for the chain (in gas token units)
    function setL1GasFeeByChain(string memory chainNamespace, uint256 l1GasFee) external;

    /// @notice                  Set TSS migration gas limit for a specific chain.
    /// @param chainNamespace    Chain Namespace
    /// @param gasLimit          TSS migration gas limit for the chain
    function setTssFundMigrationGasLimitByChain(string memory chainNamespace, uint256 gasLimit) external;

    /// @notice Get the UniversalGatewayPC address.
    function universalGatewayPC() external view returns (address);

    // =========================
    //    UC: PC20 EXPORT
    // =========================

    /// @notice                      Get gas and fee quote for a PC20 export to a destination chain.
    /// @param destChainNamespace    Destination chain (CAIP-2, e.g., "eip155:1")
    /// @param gasLimit              Caller-provided gas limit (0 = use per-chain base)
    /// @param pc20Token             PC20 token address (for protocol fee lookup)
    /// @return gasToken             Gas token PRC20 address for the destination chain
    /// @return gasFee               Gas fee (gasPrice * gasLimitUsed)
    /// @return protocolFee          Protocol fee in native PC
    /// @return gasPrice             Gas price on the destination chain
    /// @return chainNamespace       Destination chain namespace (echoed back)
    /// @return gasLimitUsed         Effective gas limit used to compute gasFee
    /// @return isFirstExport        True if pc20DeploymentGasOverhead > 0 for this chain
    function getPC20ExportGasAndFees(
        string memory destChainNamespace,
        uint256 gasLimit,
        address pc20Token
    )
        external
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
            uint256 gasPrice,
            string memory chainNamespace,
            uint256 gasLimitUsed,
            bool isFirstExport
        );

    /// @notice                      Get the PC20 deployment gas overhead for a chain.
    /// @param chainNamespace        Chain namespace
    /// @return overhead             Gas overhead (0 = no overhead)
    function pc20DeploymentGasOverhead(string memory chainNamespace) external view returns (uint256 overhead);

    /// @notice                      Set deployment gas overhead for first-ever PC20 export to a chain.
    /// @param chainNamespace        Chain namespace
    /// @param overhead              Gas overhead (0 = reset after first deployment)
    function updatePC20DeploymentGasOverhead(string memory chainNamespace, uint256 overhead) external;

    event SetPC20DeploymentGasOverhead(string chainNamespace, uint256 overhead);

    // =========================
    //    UC: PC20 REGISTRY
    // =========================

    event SetPC20Deployed(address indexed sourceAsset, string destChain, address wrapper);
    event SetPC20FactoryByChain(string chainNamespace, address factory);

    /// @notice                  Check if a PC20 wrapper is deployed for a source asset on a chain.
    /// @param sourceAsset       Source asset address on Push Chain
    /// @param destChain         Destination chain namespace
    /// @return                  True if wrapper is deployed
    function pc20Deployed(address sourceAsset, string memory destChain) external view returns (bool);

    /// @notice                  Get the wrapper address for a source asset on a chain.
    /// @param sourceAsset       Source asset address on Push Chain
    /// @param destChain         Destination chain namespace
    /// @return wrapper          Wrapper address (address(0) if not deployed)
    /// @return deployed         True if wrapper is deployed
    function getPC20Wrapper(
        address sourceAsset,
        string memory destChain
    ) external view returns (address wrapper, bool deployed);

    /// @notice                  Get the source asset for a wrapper on a chain.
    /// @param wrapper           Wrapper address on external chain
    /// @param destChain         Chain namespace
    /// @return sourceAsset      Source asset address on Push Chain
    /// @return known            True if mapping exists
    function getPC20Source(
        address wrapper,
        string memory destChain
    ) external view returns (address sourceAsset, bool known);

    /// @notice                  Mark a PC20 wrapper as deployed. Idempotent.
    /// @param sourceAsset       Source asset address on Push Chain
    /// @param destChain         Destination chain namespace
    /// @param wrapper           Deployed wrapper address on external chain
    function setWrapperDeployed(
        address sourceAsset,
        string calldata destChain,
        address wrapper
    ) external;

    /// @notice                  Set the PC20Factory address for a chain.
    /// @param chainNamespace    Chain namespace
    /// @param factory           PC20Factory address on that chain
    function updatePC20FactoryByChain(
        string memory chainNamespace,
        address factory
    ) external;

    /// @notice                  Get the PC20Factory address for a chain.
    /// @param chainNamespace    Chain namespace
    /// @return factory          PC20Factory address
    function pc20FactoryByChain(
        string memory chainNamespace
    ) external view returns (address factory);

    /// @notice                  Get the wrapper address for a source asset on a chain.
    /// @param sourceAsset       Source asset address
    /// @param destChain         Destination chain namespace
    /// @return wrapper          Wrapper address
    function pc20WrapperBySource(
        address sourceAsset,
        string memory destChain
    ) external view returns (address wrapper);

    /// @notice                  Get the source asset for a wrapper on a chain.
    /// @param destChain         Chain namespace
    /// @param wrapper           Wrapper address
    /// @return sourceAsset      Source asset address
    function pc20SourceByWrapper(
        string memory destChain,
        address wrapper
    ) external view returns (address sourceAsset);
}
