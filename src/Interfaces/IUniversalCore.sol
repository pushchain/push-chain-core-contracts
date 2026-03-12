// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev    Defines public-facing functions for UniversalCore contract.
interface IUniversalCore {
    // =========================
    //    UC: EVENTS
    // =========================

    event SetChainMeta(
        string chainNamespace,
        uint256 price,
        uint256 chainHeight,
        uint256 observedAt
    );
    event SetGasToken(string chainNamespace, address prc20);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event SetSupportedToken(address indexed prc20, bool supported);
    event SetGasPCPool(
        string chainNamespace, address pool, uint24 fee
    );
    event DepositPRC20WithAutoSwap(
        address prc20,
        uint256 amountIn,
        address pcToken,
        uint256 amountOut,
        uint24 fee,
        address recipient
    );
    event SwapAndBurnGas(
        address indexed gasToken,
        uint256 pcIn,
        uint256 gasFee,
        uint24 fee,
        address indexed caller
    );
    event SetProtocolFeeByToken(address indexed token, uint256 fee);
    event RefundUnusedGas(
        address indexed gasToken,
        uint256 amount,
        address indexed recipient,
        bool swapped,
        uint256 pcOut
    );

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
    function depositPRC20Token(
        address prc20,
        uint256 amount,
        address recipient
    ) external;

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
    function swapAndBurnGas(
        address gasToken,
        uint24 fee,
        uint256 gasFee,
        uint256 deadline,
        address caller
    ) external payable returns (uint256 gasTokenOut, uint256 refund);

    // =========================
    //    UC_3: PUBLIC GETTERS
    // =========================

    /// @notice                 Check if a PRC20 token is supported.
    /// @param prc20            PRC20 token address
    /// @return supported       Whether the token is supported
    function isSupportedToken(
        address prc20
    ) external view returns (bool supported);

    /// @notice                 Get gas token PRC20 address for a chain.
    /// @param chainNamespace   Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @return gasToken        Gas token address
    function gasTokenPRC20ByChainNamespace(
        string memory chainNamespace
    ) external view returns (address gasToken);

    /// @notice                 Get gas price for a chain.
    /// @param chainNamespace   Chain Namespace
    /// @return price           Gas price
    function gasPriceByChainNamespace(
        string memory chainNamespace
    ) external view returns (uint256 price);

    /// @notice                 Get base gas limit.
    /// @return baseGasLimit    Base gas limit
    function BASE_GAS_LIMIT()
        external
        view
        returns (uint256 baseGasLimit);

    /// @notice                 Get gas fee for a PRC20 token, split into gasFee and protocolFee.
    /// @dev                    When gasLimitWithBaseLimit is 0, falls back to BASE_GAS_LIMIT.
    /// @param _prc20           PRC20 address
    /// @param gasLimitWithBaseLimit Gas limit (0 = use BASE_GAS_LIMIT)
    /// @return gasToken        Gas token address
    /// @return gasFee          Gas fee (gasPrice * effective gas limit)
    /// @return protocolFee     Protocol fee in native PC from protocolFeeByToken mapping
    /// @return gasPrice        Gas price on the external chain
    /// @return chainNamespace  Source chain namespace
    function getOutboundTxGasAndFees(
        address _prc20,
        uint256 gasLimitWithBaseLimit
    )
        external
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
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
    function setProtocolFeeByToken(address token, uint256 fee) external;

    /// @notice Get the UniversalGatewayPC address.
    function universalGatewayPC() external view returns (address);
}
