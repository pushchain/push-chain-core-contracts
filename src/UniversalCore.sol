// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./interfaces/IPRC20.sol";
import "./interfaces/IUniswapV3.sol";
import "./interfaces/IUniversalCore.sol";
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
 *           - Generation of supported PRC20 tokens, and transfering it to accurate recipients.
 *           - Setting up the gas tokens for each chain.
 *           - Setting up the gas price for each chain.
 *           - Maintaining a registry of uniswap v3 pools for each token pair.
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

    /// @notice Map to know the gas price of each chain given a chain id.
    mapping(string => uint256) public gasPriceByChainId;

    /// @notice Map to know the PRC20 address of a token given a chain id, ex pETH, pBNB etc.
    mapping(string => address) public gasTokenPRC20ByChainId;

    /// @notice Map to know Uniswap V3 pool of PC/PRC20 given a chain id.
    mapping(string => address) public gasPCPoolByChainId;

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

    /// @notice Mapping for indicating an official PRC20 supported token
    mapping(address => bool) public isSupportedToken;

    modifier onlyUEModule() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert UniversalCoreErrors.CallerIsNotUEModule();
        _;
    }

    modifier onlyOwner() {
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
        uint256 minPCOut, // 0 = calculate from slippage tolerance
        uint256 deadline // 0 = use default
    ) external onlyUEModule whenNotPaused nonReentrant {
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert UniversalCoreErrors.InvalidTarget();
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        if (!isAutoSwapSupported[prc20]) revert UniversalCoreErrors.AutoSwapNotSupported();

        // Use default fee tier if not provided
        if (fee == 0) {
            fee = defaultFeeTier[prc20];
            if (fee == 0) revert UniversalCoreErrors.InvalidFeeTier();
        }

        if (deadline == 0) {
            deadline = block.timestamp + (defaultDeadlineMins * 1 minutes);
        }

        if (block.timestamp > deadline) revert CommonErrors.DeadlineExpired();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            prc20 < wPCContractAddress ? prc20 : wPCContractAddress,
            prc20 < wPCContractAddress ? wPCContractAddress : prc20,
            fee
        );
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        // Calculate minimum output if not provided
        if (minPCOut == 0) {
            uint256 expectedOutput = getSwapQuote(prc20, wPCContractAddress, fee, amount);
            // Calculate minimum output based on slippage tolerance
            minPCOut = calculateMinOutput(expectedOutput, prc20);
        }
        IPRC20(prc20).deposit(address(this), amount);
        IPRC20(prc20).approve(uniswapV3SwapRouterAddress, amount);

        // Swap PRC20 -> native PC (wrapped PC) via ExactInputSingle
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: prc20,
            tokenOut: wPCContractAddress,
            fee: fee,
            recipient: target,
            deadline: deadline,
            amountIn: amount,
            amountOutMinimum: minPCOut,
            sqrtPriceLimitX96: 0
        });

        uint256 pcOut = ISwapRouter(uniswapV3SwapRouterAddress).exactInputSingle(params);
        if (pcOut < minPCOut) revert UniversalCoreErrors.SlippageExceeded();

        IPRC20(prc20).approve(uniswapV3SwapRouterAddress, 0);

        emit DepositPRC20WithAutoSwap(prc20, amount, wPCContractAddress, pcOut, fee, target);
    }

    /**
     * @dev Set the gas PC pool for a chain
     * @param chainID Chain ID
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(string memory chainID, address gasToken, uint24 fee) external onlyRole(MANAGER_ROLE) {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
            wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
            fee
        );
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        gasPCPoolByChainId[chainID] = pool;
        emit SetGasPCPool(chainID, pool, fee);
    }

    /**
     * @dev Fungible module updates the gas price oracle periodically.
     * @param chainID Chain ID
     * @param price New gas price
     */
    function setGasPrice(string memory chainID, uint256 price) external onlyRole(MANAGER_ROLE) {
        gasPriceByChainId[chainID] = price;
        emit SetGasPrice(chainID, price);
    }

    /**
     * @dev Setter for gasTokenPRC20ByChainId map.
     * @param chainID Chain ID
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(string memory chainID, address prc20) external onlyRole(MANAGER_ROLE) {
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        gasTokenPRC20ByChainId[chainID] = prc20;
        emit SetGasToken(chainID, prc20);
    }

     /**
     * @notice Set auto-swap support for a token
     * @param token Token address
     * @param supported Whether the token supports auto-swap
     */
    function setAutoSwapSupported(address token, bool supported) external onlyOwner {
        isAutoSwapSupported[token] = supported;
    }

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert CommonErrors.ZeroAddress();
        wPCContractAddress = addr;
    }

    /**
     * @dev Setter for uniswap V3 addresses.
     * @param factory Uniswap V3 Factory address
     * @param swapRouter Uniswap V3 SwapRouter address
     * @param quoter Uniswap V3 Quoter address
     */
    function setUniswapV3Addresses(address factory, address swapRouter, address quoter) external onlyOwner {
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
    function setDefaultFeeTier(address token, uint24 feeTier) external onlyOwner {
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
    function setSlippageTolerance(address token, uint256 tolerance) external onlyOwner {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        if (tolerance > 5000) revert UniversalCoreErrors.InvalidSlippageTolerance(); // Max 50%
        slippageTolerance[token] = tolerance;
        }

    /**
     * @notice Set default deadline in minutes
     * @param minutesValue Default deadline in minutes
     */
    function setDefaultDeadlineMins(uint256 minutesValue) external onlyOwner {
        defaultDeadlineMins = minutesValue;
        emit SetDefaultDeadlineMins(minutesValue);
    }

    /// @notice Update the base gas limit for the cross-chain outbound transactions.
    /// @param  gasLimit New base gas limit
    function updateBaseGasLimit(uint256 gasLimit) external onlyOwner {
        BASE_GAS_LIMIT = gasLimit;
    }

    
    /**
     * @notice Pause the contract - stops all deposit functions
     * @dev Can only be called by the owner
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpause the contract - resumes all deposit functions
     * @dev Can only be called by the owner
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    //========= Public Helpers =========//

    /**
     * @notice              Gets quote for token swap using Uniswap V3 Quoter
     * @param tokenIn       Input token
     * @param tokenOut      Output token
     * @param fee           Fee tier
     * @param amountIn      Input amount
     * @return amountOut    Expected output amount
     */
    function getSwapQuote(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn)
        public
        returns (uint256)
    {
        // Use QuoterV2 interface with struct parameter
        IQuoterV2.QuoteExactInputSingleParams memory params = IQuoterV2.QuoteExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            fee: fee,
            sqrtPriceLimitX96: 0
        });

        // Call QuoterV2 directly - it handles the revert internally and returns the values
        (uint256 amountOut, , , ) = IQuoterV2(uniswapV3QuoterAddress).quoteExactInputSingle(params);
        
        return amountOut;
    }


    /**
     * @notice                  Calculates minimum output based on slippage tolerance
     * @param expectedOutput    Expected output amount from quote (in PC tokens)
     * @param token             Token address to get slippage tolerance for
     * @return minAmountOut     Minimum output amount (in PC tokens)
     */
    function calculateMinOutput(uint256 expectedOutput, address token) internal view returns (uint256) {
        uint256 tolerance = slippageTolerance[token];
        if (tolerance == 0) {
            tolerance = 300; // Default 3% slippage tolerance
        }

        // Ensure expectedOutput is not 0 to avoid calculation issues
        if (expectedOutput == 0) {
            return 0;
        }

        // Calculate minimum output: expectedOutput * (10000 - tolerance) / 10000
        return (expectedOutput * (10000 - tolerance)) / 10000;
    }

    /**
     * @inheritdoc IUniversalCore
     */
    function withdrawGasFee(address _prc20) public view returns (address gasToken, uint256 gasFee) {
        string memory chainID = IPRC20(_prc20).SOURCE_CHAIN_ID();

        gasToken = gasTokenPRC20ByChainId[chainID];
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        uint256 price = gasPriceByChainId[chainID];
        if (price == 0) revert UniversalCoreErrors.ZeroGasPrice();

        gasFee = price * BASE_GAS_LIMIT + IPRC20(_prc20).PC_PROTOCOL_FEE();
    }

    /**
     * @inheritdoc IUniversalCore
     */
    function withdrawGasFeeWithGasLimit(address _prc20, uint256 gasLimit) public view returns (address gasToken, uint256 gasFee) {
        string memory chainID = IPRC20(_prc20).SOURCE_CHAIN_ID();

        gasToken = gasTokenPRC20ByChainId[chainID];
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        uint256 price = gasPriceByChainId[chainID];
        if (price == 0) revert UniversalCoreErrors.ZeroGasPrice();

        gasFee = price * gasLimit + IPRC20(_prc20).PC_PROTOCOL_FEE();
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
