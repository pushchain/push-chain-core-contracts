// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IUniversalCore
/// @notice Interface for the UniversalCore contract.
/// @dev Defines functions for UniversalCore contract callable by fungible module.
interface IUniversalCore {
    // =========================
    //           Universal Core Events
    // =========================    
    event SetChainMeta(string chainNamespace, uint256 price, uint256 chainHeight, uint256 observedAt);
    event SetGasToken(string chainNamespace, address prc20);
    event SetDefaultDeadlineMins(uint256 minutesValue);
    event SetSupportedToken(address indexed prc20, bool supported);
    event SetGasPCPool(string chainNamespace, address pool, uint24 fee);
    event DepositPRC20WithAutoSwap(address prc20, uint256 amountIn, address pcToken, uint256 amountOut, uint24 fee, address target);
    event SwapAndBurnGas(
        address indexed gasToken, address indexed vault,
        uint256 pcIn, uint256 gasFee, uint256 protocolFee,
        uint24 fee, address indexed caller
    );
    event RefundUnusedGas(
        address indexed gasToken,
        uint256 amount,
        address indexed recipient,
        bool swapped,
        uint256 pcOut
    );
    // =========================
    //           Universal Core Functions
    // =========================  

    /**
     * @notice Check if a PRC20 token is supported
     * @param prc20 PRC20 token address
     * @return supported Whether the token is supported
     */
    function isSupportedToken(address prc20) external view returns (bool supported);
    /**
     * @notice Deposits PRC20 tokens to the provided target address.
     * @dev    Can only be called by the Universal Executor Module.
     *         For any inbound transactions of moving supported tokens from external chains to Push Chain,
     *         the Universal Executor Module uses this function to deposit the tokens to the target address.
     *         The target address can be any address of the user's choice.
     * @param prc20 PRC20 address for deposit
     * @param amount Amount to deposit
     * @param target Address to deposit tokens to
     */
    function depositPRC20Token(address prc20, uint256 amount, address target) external;

    /**
     * @notice Deposits PRC20 tokens and automatically swaps them to native PC before sending to target.
     * @dev    Can only be called by the Universal Executor Module.
     *         Can only be called if the PRC20 token is in the auto-swap supported list. ( eg pETH, pSOL, pUSDC etc.)
     *         If no pool exists, reverts with appropriate error. Although all auto-swap supported tokens are expected to have a pool.
     *         Default values are used when parameters are set to 0. ( fee = defaultFeeTier[prc20], deadline = block.timestamp + (defaultDeadlineMins * 1 minutes) )
     *         target address always receive the swapped native PC tokens.
     *         The function is called directly by the Universal Executor Module and is also gasless.
     * @param prc20 PRC20 address for deposit and swap
     * @param amount Amount to deposit and swap
     * @param target Address to receive the swapped native PC tokens
     * @param fee Uniswap V3 fee tier for the pool (0 = use default)
     * @param minPCOut Minimum amount of native PC expected from the swap (must be > 0)
     * @param deadline Timestamp after which the transaction will revert (0 = use default)
     */
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address target,
        uint24 fee,
        uint256 minPCOut,
        uint256 deadline
    ) external;


    // =========================
    //           Getter Functions
    // =========================

    /**
     * @notice Get gas token PRC20 address for a chain
     * @param chainNamespace Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
     * @return gasToken Gas token address
     */
    function gasTokenPRC20ByChainNamespace(string memory chainNamespace) external view returns (address gasToken);

    /**
     * @notice Get gas price for a chain
     * @param chainNamespace Chain Namespace
     * @return price Gas price
     */
    function gasPriceByChainNamespace(string memory chainNamespace) external view returns (uint256 price);

    /**
     * @notice Get base gas limit for a chain
     * @return baseGasLimit Base gas limit
     */
    function BASE_GAS_LIMIT() external view returns (uint256 baseGasLimit);

    /**
     * @notice Get gas fee for a PRC20 token, split into gasFee and protocolFee.
     * @dev    When gasLimit is 0, falls back to BASE_GAS_LIMIT.
     * @param _prc20 PRC20 address
     * @param gasLimit Gas limit (0 = use BASE_GAS_LIMIT)
     * @return gasToken Gas token address
     * @return gasFee Gas fee (price * effective gas limit)
     * @return protocolFee Protocol fee from PRC20
     * @return chainNamespace Source chain namespace
     */
    function getOutboundTxGasAndFees(address _prc20, uint256 gasLimit)
        external
        view
        returns (address gasToken, uint256 gasFee, uint256 protocolFee, string memory chainNamespace);

    /// @notice Swap native PC for gas token PRC20, burn gasFee, send protocolFee to vault
    /// @param gasToken           Gas token PRC20 address
    /// @param vault              Vault address to receive protocol fee
    /// @param fee                Uniswap V3 fee tier (0 = use default)
    /// @param gasFee             Gas fee amount to burn
    /// @param protocolFee        Protocol fee amount to send to vault
    /// @param deadline           Swap deadline (0 = use default)
    /// @param caller             Address to receive unused PC refund
    /// @return gasTokenOut       Total gas token swapped (gasFee + protocolFee)
    /// @return refund            Unused PC refunded to caller
    function swapAndBurnGas(
        address gasToken, address vault, uint24 fee,
        uint256 gasFee, uint256 protocolFee, uint256 deadline,
        address caller
    ) external payable returns (uint256 gasTokenOut, uint256 refund);

    /// @notice Refund unused gas to recipient, optionally swapping PRC20 to WPC
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

    /// @notice Get the GATEWAY_ROLE identifier
    function GATEWAY_ROLE() external pure returns (bytes32);
}