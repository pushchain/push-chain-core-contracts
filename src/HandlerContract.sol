// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./interfaces/IPRC20.sol";
import "./interfaces/IUniswapV3.sol";
import "./interfaces/IHandler.sol";
import {HandlerErrors} from "./libraries/Errors.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

/**
 * @title HandlerContract
 * @notice The HanclerContract acts as the main HANDLER for all functionalities needed by the interoperability feature of Push Chain.
 * @dev    The HandlerContract primarily handles the following functionalities:
 *         - Generation of supported PRC20 tokens, and transfering it to accurate recipients.
 *         - Setting up the gas tokens for each chain.
 *         - Setting up the gas price for each chain.
 *         - Maintaining a registry of uniswap v3 pools for each token pair.
 * @dev    All imperative functionalities are handled by the Universal Executor Module.
 */
contract HandlerContract is IHandler, Initializable, ReentrancyGuardUpgradeable, AccessControlUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice Map to know the gas price of each chain given a chain id.
    mapping(uint256 => uint256) public gasPriceByChainId;

    /// @notice Map to know the PRC20 address of a token given a chain id, ex pETH, pBNB etc.
    mapping(uint256 => address) public gasTokenPRC20ByChainId;

    /// @notice Map to know Uniswap V3 pool of PC/PRC20 given a chain id.
    mapping(uint256 => address) public gasPCPoolByChainId;

    /// @notice Supproted token list for auto swap to PC using Uniswap V3.
    mapping(address => bool) public isAutoSwapSupported;

    /// @notice Fungible address is always the same, it's on protocol level.
    address public immutable UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    /// @notice Uniswap V3 addresses.
    address public uniswapV3FactoryAddress;
    address public uniswapV3SwapRouterAddress;
    address public uniswapV3QuoterAddress;

    /// @notice Address of the wrapped PC to interact with Uniswap V3.
    address public wPCContractAddress;

    modifier onlyUEModule() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert HandlerErrors.CallerIsNotUEModule();
        _;
    }

    modifier onlyOwner() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert HandlerErrors.CallerIsNotOwner();
        _;
    }

    /**
     * @dev Only fungible module can deploy a handler contract.
     * @param wpc_ Address of the wrapped PC token
     * @param uniswapV3Factory_ Address of the Uniswap V3 factory
     * @param uniswapV3SwapRouter_ Address of the Uniswap V3 swap router
     * @param uniswapV3Quoter_ Address of the Uniswap V3 quoter
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializer function for the upgradeable contract.
     * @param wpc_ Address of the wrapped PC token
     * @param uniswapV3Factory_ Address of the Uniswap V3 factory
     * @param uniswapV3SwapRouter_ Address of the Uniswap V3 swap router
     * @param uniswapV3Quoter_ Address of the Uniswap V3 quoter
     */
    function initialize(address wpc_, address uniswapV3Factory_, address uniswapV3SwapRouter_, address uniswapV3Quoter_)
        public
        virtual
        initializer
    {
        __ReentrancyGuard_init();
        __AccessControl_init();

        // Grant the deployer the default admin role
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        wPCContractAddress = wpc_;
        uniswapV3FactoryAddress = uniswapV3Factory_;
        uniswapV3SwapRouterAddress = uniswapV3SwapRouter_;
        uniswapV3QuoterAddress = uniswapV3Quoter_;

        emit SystemContractDeployed();
    }

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
    function depositPRC20Token(
        address prc20,
        uint256 amount,
        address target
    ) external onlyUEModule{
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert HandlerErrors.InvalidTarget();

        IPRC20(prc20).deposit(target, amount);
    }

    /**
     * @notice Deposits PRC20 tokens and automatically swaps them to native PC before sending to target.
     * @dev    Can only be called by the Universal Executor Module.
     *         Can only be called if the PRC20 token is in the auto-swap supported list.
     *         If no pool exists, reverts with appropriate error. Although all auto-swap supported tokens are expected to have a pool.
     * @param prc20 PRC20 address for deposit and swap
     * @param amount Amount to deposit and swap
     * @param target Address to receive the swapped native PC tokens
     * @param fee Uniswap V3 fee tier for the pool
     * @param minPCOut Minimum amount of native PC expected from the swap
     * @param deadline Timestamp after which the transaction will revert
     */
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address target,
        uint24 fee,
        uint256 minPCOut,
        uint256 deadline
    ) external onlyUEModule nonReentrant {
        // Validate inputs
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert HandlerErrors.InvalidTarget();
        if (block.timestamp > deadline) revert HandlerErrors.DeadlineExpired();
        if (prc20 == address(0)) revert HandlerErrors.ZeroAddress();
        if (amount == 0) revert HandlerErrors.ZeroAmount();
        
        if (!isAutoSwapSupported[prc20]) revert HandlerErrors.AutoSwapNotSupported();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            prc20 < wPCContractAddress ? prc20 : wPCContractAddress,
            prc20 < wPCContractAddress ? wPCContractAddress : prc20,
            fee
        );
        if (pool == address(0)) revert HandlerErrors.PoolNotFound();

        // Deposit PRC20 tokens to this contract
        IPRC20(prc20).deposit(address(this), amount);

        // Approve Uniswap V3 router to spend PRC20 tokens
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
        if (pcOut < minPCOut) revert HandlerErrors.SlippageExceeded();

        // Clear approval
        IPRC20(prc20).approve(uniswapV3SwapRouterAddress, 0);

        emit DepositPRC20WithAutoSwap(prc20, amount, wPCContractAddress, pcOut, fee, target);
    }

    /**
     * @dev Set the gas PC pool for a chain
     * @param chainID Chain ID
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(uint256 chainID, address gasToken, uint24 fee) external onlyUEModule {
        if (gasToken == address(0)) revert HandlerErrors.ZeroAddress();
        
        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
            wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
            fee
        );
        if (pool == address(0)) revert HandlerErrors.PoolNotFound();

        gasPCPoolByChainId[chainID] = pool;
        emit SetGasPCPool(chainID, pool, fee);
    }

    /**
     * @dev Fungible module updates the gas price oracle periodically.
     * @param chainID Chain ID
     * @param price New gas price
     */
    function setGasPrice(uint256 chainID, uint256 price) external onlyUEModule {
        gasPriceByChainId[chainID] = price;
        emit SetGasPrice(chainID, price);
    }

    /**
     * @dev Setter for gasTokenPRC20ByChainId map.
     * @param chainID Chain ID
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(uint256 chainID, address prc20) external onlyUEModule {
        if (prc20 == address(0)) revert HandlerErrors.ZeroAddress();
        gasTokenPRC20ByChainId[chainID] = prc20;
        emit SetGasToken(chainID, prc20);
    }

    function setAutoSwapSupported(address token, bool supported) external onlyOwner {
        isAutoSwapSupported[token] = supported;
        emit SetAutoSwapSupported(token, supported);
    }

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert HandlerErrors.ZeroAddress();
        wPCContractAddress = addr;
        emit SetWPC(addr);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
