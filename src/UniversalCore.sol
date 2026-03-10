// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./interfaces/IPRC20.sol";
import "./interfaces/IUniswapV3.sol";
import "./interfaces/IUniversalCore.sol";
import {IWPC} from "./interfaces/IWPC.sol";
import {UniversalCoreErrors, CommonErrors} from "./libraries/Errors.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title   UniversalCore
 * @notice  The UniversalCore acts as the core contract for all functionalities needed by the interoperability feature of Push Chain.
 * @dev     The UniversalCore primarily handles the following functionalities:
 *           - Generation of supported PRC-20 tokens, and transferring it to accurate recipients.
 *           - Setting up the gas tokens for each chain.
 *           - Setting up the gas price for each chain.
 *           - Maintaining a registry of Uniswap V3 pools for each token pair.
 * @dev    All imperative functionalities are handled by the Universal Executor Module.
 */

contract UniversalCore is
    IUniversalCore,
    Initializable,
    ReentrancyGuardUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    /// @notice Map to know the gas price of each chain given a chain namespace.
    mapping(string => uint256) public gasPriceByChainNamespace;

    /// @notice Map to know the PRC20 address of a token given a chain namespace, ex pETH, pBNB etc.
    mapping(string => address) public gasTokenPRC20ByChainNamespace;

    /// @notice Map to know Uniswap V3 pool of PC/PRC20 given a chain namespace.
    mapping(string => address) public gasPCPoolByChainNamespace;

    /// @notice Supproted token list for auto swap to PC using Uniswap V3.
    mapping(address => bool) public isAutoSwapSupported;

    /// @notice Default fee tier for each token (0 = not set)
    mapping(address => uint24) public defaultFeeTier;

    /// @notice Slippage tolerance for each token in basis points (e.g., 300 = 3%)
    mapping(address => uint256) public slippageTolerance;

    /// @notice Default deadline in minutes for swaps
    uint256 public defaultDeadlineMins = 20;

    /// @notice Fungible address is always the same, it's on protocol level.
    address public immutable UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    /// @notice Uniswap V3 addresses.
    address public uniswapV3FactoryAddress;
    address public uniswapV3SwapRouterAddress;
    address public uniswapV3QuoterAddress;

    /// @notice Address of the wrapped PC to interact with Uniswap V3.
    address public wPCContractAddress;

    /// @notice Base gas limit for the cross-chain outbound transactions.
    uint256 public BASE_GAS_LIMIT = 500_000;

    /// @notice Role for managing gas-related configurations
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    /// @notice Role for gateway contracts that can swap PC for gas tokens
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");

    /// @notice Mapping for indicating an official PRC20 supported token
    mapping(address => bool) public isSupportedToken;

    /// @notice External chain block height last observed by relayer
    mapping(string => uint256) public chainHeightByChainNamespace;

    /// @notice Timestamp when the chain meta was last observed
    mapping(string => uint256) public timestampObservedAtByChainNamespace;

    modifier onlyUEModule() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert UniversalCoreErrors.CallerIsNotUEModule();
        _;
    }

    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert CommonErrors.InvalidOwner();
        _;
    }

    constructor() {
        _disableInitializers();
    }

    /**
     * @dev                         Initializer function for the upgradeable contract.
     * @param wpc_                  Address of the wrapped PC token
     * @param uniswapV3Factory_     Address of the Uniswap V3 factory
     * @param uniswapV3SwapRouter_  Address of the Uniswap V3 swap router
     * @param uniswapV3Quoter_      Address of the Uniswap V3 quoter
     */
    function initialize(address wpc_, address uniswapV3Factory_, address uniswapV3SwapRouter_, address uniswapV3Quoter_)
        public
        virtual
        initializer
    {
        __ReentrancyGuard_init();
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MANAGER_ROLE, UNIVERSAL_EXECUTOR_MODULE);

        wPCContractAddress = wpc_;
        uniswapV3FactoryAddress = uniswapV3Factory_;
        uniswapV3SwapRouterAddress = uniswapV3SwapRouter_;
        uniswapV3QuoterAddress = uniswapV3Quoter_;
    }

    /**
     * @notice Set whether a PRC20 token is supported
     * @param prc20 PRC20 token address
     * @param supported Whether the token is supported
     */
    function setSupportedToken(address prc20, bool supported) external onlyRole(MANAGER_ROLE) {
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        isSupportedToken[prc20] = supported;
        emit SetSupportedToken(prc20, supported);
    }

    /**
     * @inheritdoc IUniversalCore
     */
    function depositPRC20Token(address prc20, uint256 amount, address target) external onlyUEModule whenNotPaused {
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert UniversalCoreErrors.InvalidTarget();
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        IPRC20(prc20).deposit(target, amount);
    }

    /**
     * @inheritdoc IUniversalCore
     */
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address target,
        uint24 fee, // 0 = use default
        uint256 minPCOut,
        uint256 deadline // 0 = use default
    ) external onlyUEModule whenNotPaused nonReentrant {
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert UniversalCoreErrors.InvalidTarget();
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        (uint256 pcOut, uint24 resolvedFee) = _autoSwap(prc20, amount, target, fee, minPCOut, deadline);

        emit DepositPRC20WithAutoSwap(prc20, amount, wPCContractAddress, pcOut, resolvedFee, target);
    }

    /// @inheritdoc IUniversalCore
    function refundUnusedGas(
        address gasToken,
        uint256 amount,
        address recipient,
        bool withSwap,
        uint24 fee,
        uint256 minPCOut
    ) external onlyUEModule whenNotPaused nonReentrant {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        uint256 pcOut;

        if (!withSwap) {
            IPRC20(gasToken).deposit(recipient, amount);
        } else {
            if (minPCOut == 0) revert UniversalCoreErrors.MinPCOutRequired();
            (pcOut,) = _autoSwap(gasToken, amount, recipient, fee, minPCOut, 0);
        }

        emit RefundUnusedGas(gasToken, amount, recipient, withSwap, pcOut);
    }

    /**
     * @dev Set the gas PC pool for a chain
     * @param chainNamespace Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(string memory chainNamespace, address gasToken, uint24 fee) external onlyRole(MANAGER_ROLE) {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress)
            .getPool(
                wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
                wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
                fee
            );
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        gasPCPoolByChainNamespace[chainNamespace] = pool;
        emit SetGasPCPool(chainNamespace, pool, fee);
    }

    /// @notice Sets gas price, chain height, and observation timestamp for a chain.
    /// @param chainNamespace Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param price Gas price on the external chain
    /// @param chainHeight Block height observed on the external chain
    /// @param observedAt Timestamp when the observation was made
    function setChainMeta(string memory chainNamespace, uint256 price, uint256 chainHeight, uint256 observedAt)
        external
        onlyRole(MANAGER_ROLE)
    {
        gasPriceByChainNamespace[chainNamespace] = price;
        chainHeightByChainNamespace[chainNamespace] = chainHeight;
        timestampObservedAtByChainNamespace[chainNamespace] = observedAt;
        emit SetChainMeta(chainNamespace, price, chainHeight, observedAt);
    }

    /**
     * @dev Setter for gasTokenPRC20ByChainNamespace map.
     * @param chainNamespace Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(string memory chainNamespace, address prc20) external onlyRole(MANAGER_ROLE) {
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        gasTokenPRC20ByChainNamespace[chainNamespace] = prc20;
        emit SetGasToken(chainNamespace, prc20);
    }

    /**
     * @notice Set auto-swap support for a token
     * @param token Token address
     * @param supported Whether the token supports auto-swap
     */
    function setAutoSwapSupported(address token, bool supported) external onlyAdmin {
        isAutoSwapSupported[token] = supported;
    }

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external onlyAdmin {
        if (addr == address(0)) revert CommonErrors.ZeroAddress();
        wPCContractAddress = addr;
    }

    /**
     * @dev Setter for uniswap V3 addresses.
     * @param factory Uniswap V3 Factory address
     * @param swapRouter Uniswap V3 SwapRouter address
     * @param quoter Uniswap V3 Quoter address
     */
    function setUniswapV3Addresses(address factory, address swapRouter, address quoter) external onlyAdmin {
        if (factory == address(0) || swapRouter == address(0) || quoter == address(0)) {
            revert CommonErrors.ZeroAddress();
        }
        uniswapV3FactoryAddress = factory;
        uniswapV3SwapRouterAddress = swapRouter;
        uniswapV3QuoterAddress = quoter;
    }

    /**
     * @notice Set default fee tier for a token
     * @param token Token address
     * @param feeTier Fee tier (500, 3000, 10000)
     */
    function setDefaultFeeTier(address token, uint24 feeTier) external onlyAdmin {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        if (feeTier != 500 && feeTier != 3000 && feeTier != 10000) {
            revert UniversalCoreErrors.InvalidFeeTier();
        }
        defaultFeeTier[token] = feeTier;
    }

    /**
     * @notice Set slippage tolerance for a token
     * @param token Token address
     * @param tolerance Slippage tolerance in basis points (e.g., 300 = 3%)
     */
    function setSlippageTolerance(address token, uint256 tolerance) external onlyAdmin {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        if (tolerance > 5000) revert UniversalCoreErrors.InvalidSlippageTolerance(); // Max 50%
        slippageTolerance[token] = tolerance;
    }

    /**
     * @notice Set default deadline in minutes
     * @param minutesValue Default deadline in minutes
     */
    function setDefaultDeadlineMins(uint256 minutesValue) external onlyAdmin {
        defaultDeadlineMins = minutesValue;
        emit SetDefaultDeadlineMins(minutesValue);
    }

    /// @notice Update the base gas limit for the cross-chain outbound transactions.
    /// @param  gasLimit New base gas limit
    function updateBaseGasLimit(uint256 gasLimit) external onlyAdmin {
        BASE_GAS_LIMIT = gasLimit;
    }

    /**
     * @notice Pause the contract - stops all deposit functions
     * @dev Can only be called by the owner
     */
    function pause() external onlyAdmin {
        _pause();
    }

    /**
     * @notice Unpause the contract - resumes all deposit functions
     * @dev Can only be called by the owner
     */
    function unpause() external onlyAdmin {
        _unpause();
    }

    /**
     * @inheritdoc IUniversalCore
     */
    function getOutboundTxGasAndFees(address _prc20, uint256 gasLimit)
        public
        view
        returns (address gasToken, uint256 gasFee, uint256 protocolFee, string memory chainNamespace)
    {
        if (gasLimit == 0) {
            gasLimit = BASE_GAS_LIMIT;
        }
        chainNamespace = IPRC20(_prc20).SOURCE_CHAIN_NAMESPACE();

        gasToken = gasTokenPRC20ByChainNamespace[chainNamespace];
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        uint256 price = gasPriceByChainNamespace[chainNamespace];
        if (price == 0) revert UniversalCoreErrors.ZeroGasPrice();

        gasFee = price * gasLimit;
        protocolFee = IPRC20(_prc20).PC_PROTOCOL_FEE();
    }

    /// @notice Accept native PC transfers (e.g., from WPC withdraw)
    receive() external payable {}

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
        address gasToken,
        address vault,
        uint24 fee,
        uint256 gasFee,
        uint256 protocolFee,
        uint256 deadline,
        address caller
    ) external payable onlyRole(GATEWAY_ROLE) whenNotPaused nonReentrant returns (uint256 gasTokenOut, uint256 refund) {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();
        if (vault == address(0)) revert CommonErrors.ZeroAddress();
        if (caller == address(0)) revert CommonErrors.ZeroAddress();
        if (msg.value == 0) revert CommonErrors.ZeroAmount();
        if (gasFee == 0) revert CommonErrors.ZeroAmount();

        uint256 totalRequiredGasOut = gasFee + protocolFee;

        if (fee == 0) {
            fee = defaultFeeTier[gasToken];
            if (fee == 0) revert UniversalCoreErrors.InvalidFeeTier();
        }

        if (deadline == 0) {
            deadline = block.timestamp + (defaultDeadlineMins * 1 minutes);
        }
        if (block.timestamp > deadline) revert CommonErrors.DeadlineExpired();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress)
            .getPool(
                wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
                wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
                fee
            );
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        IWPC(wPCContractAddress).deposit{value: msg.value}();

        IERC20(wPCContractAddress).approve(uniswapV3SwapRouterAddress, msg.value);

        ISwapRouter.ExactOutputSingleParams memory params = ISwapRouter.ExactOutputSingleParams({
            tokenIn: wPCContractAddress,
            tokenOut: gasToken,
            fee: fee,
            recipient: address(this),
            deadline: deadline,
            amountOut: totalRequiredGasOut,
            amountInMaximum: msg.value,
            sqrtPriceLimitX96: 0
        });

        uint256 amountInUsed = ISwapRouter(uniswapV3SwapRouterAddress).exactOutputSingle(params);
        IERC20(wPCContractAddress).approve(uniswapV3SwapRouterAddress, 0);

        // Burn the gas fee portion
        IPRC20(gasToken).burn(gasFee);
        // Transfer the protocol fee portion to the vaultPC
        if (protocolFee > 0) {
            IERC20(gasToken).safeTransfer(vault, protocolFee);
        }

        gasTokenOut = totalRequiredGasOut;
        refund = msg.value - amountInUsed;
        if (refund > 0) {
            IWPC(wPCContractAddress).withdraw(refund);
            (bool ok,) = caller.call{value: refund}("");
            if (!ok) revert CommonErrors.TransferFailed();
        }

        emit SwapAndBurnGas(gasToken, vault, amountInUsed, gasFee, protocolFee, fee, caller);
    }

    /// @dev Swap PRC20 to WPC via Uniswap V3 exactInputSingle.
    function _autoSwap(address prc20, uint256 amount, address recipient, uint24 fee, uint256 minPCOut, uint256 deadline)
        private
        returns (uint256 pcOut, uint24 resolvedFee)
    {
        if (!isAutoSwapSupported[prc20]) revert UniversalCoreErrors.AutoSwapNotSupported();

        resolvedFee = fee;
        if (resolvedFee == 0) {
            resolvedFee = defaultFeeTier[prc20];
            if (resolvedFee == 0) revert UniversalCoreErrors.InvalidFeeTier();
        }

        if (deadline == 0) {
            deadline = block.timestamp + (defaultDeadlineMins * 1 minutes);
        }
        if (block.timestamp > deadline) revert CommonErrors.DeadlineExpired();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress)
            .getPool(
                prc20 < wPCContractAddress ? prc20 : wPCContractAddress,
                prc20 < wPCContractAddress ? wPCContractAddress : prc20,
                resolvedFee
            );
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        if (minPCOut == 0) revert CommonErrors.ZeroAmount();

        IPRC20(prc20).deposit(address(this), amount);
        IPRC20(prc20).approve(uniswapV3SwapRouterAddress, amount);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: prc20,
            tokenOut: wPCContractAddress,
            fee: resolvedFee,
            recipient: recipient,
            deadline: deadline,
            amountIn: amount,
            amountOutMinimum: minPCOut,
            sqrtPriceLimitX96: 0
        });

        pcOut = ISwapRouter(uniswapV3SwapRouterAddress).exactInputSingle(params);
        if (pcOut < minPCOut) revert UniversalCoreErrors.SlippageExceeded();

        IPRC20(prc20).approve(uniswapV3SwapRouterAddress, 0);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
