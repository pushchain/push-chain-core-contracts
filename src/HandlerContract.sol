// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./interfaces/IPRC20.sol";
import "./interfaces/IUniversalContract.sol";
import "./interfaces/IUniswapV3.sol";
import "./interfaces/IHandler.sol";
import {HandlerErrors as Errors} from "./libraries/Errors.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

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
contract HandlerContract is IHandler, Initializable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice Map to know the gas price of each chain given a chain id.
    mapping(uint256 => uint256) public gasPriceByChainId;

    /// @notice Map to know the PRC20 address of a token given a chain id, ex pETH, pBNB etc.
    mapping(uint256 => address) public gasTokenPRC20ByChainId;

    /// @notice Map to know Uniswap V3 pool of PC/PRC20 given a chain id.
    mapping(uint256 => address) public gasPCPoolByChainId;

    /// @notice Fungible address is always the same, it's on protocol level.
    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    /// @notice Uniswap V3 addresses.
    address public uniswapV3FactoryAddress;
    address public uniswapV3SwapRouterAddress;
    address public uniswapV3QuoterAddress;

    /// @notice Address of the wrapped PC to interact with Uniswap V3.
    address public wPCContractAddress;

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
        initializer
    {
        __ReentrancyGuard_init();

        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();

        wPCContractAddress = wpc_;
        uniswapV3FactoryAddress = uniswapV3Factory_;
        uniswapV3SwapRouterAddress = uniswapV3SwapRouter_;
        uniswapV3QuoterAddress = uniswapV3Quoter_;

        emit SystemContractDeployed();
    }

    /**
     * @dev Deposit foreign coins into PRC20 and call user specified contract on Push Chain.
     * @param context Context data for deposit
     * @param prc20 PRC20 address for deposit
     * @param amount Amount to deposit
     * @param target Contract address to make a call after deposit
     * @param message Calldata for a call
     */
    function depositAndCall(
        pContext calldata context,
        address prc20,
        uint256 amount,
        address target,
        bytes calldata message
    ) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert Errors.InvalidTarget();

        IPRC20(prc20).deposit(target, amount);
        //IUniversalContract(target).onCrossChainCall(context, prc20, amount, message); - NOT NEEDED FOR NOW
    }

    /**
     * @dev Set the gas PC pool for a chain
     * @param chainID Chain ID
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(uint256 chainID, address gasToken, uint24 fee) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        // gasToken must equal gasTokenPRC20ByChainId[chainID]
        if (gasToken != gasTokenPRC20ByChainId[chainID]) revert Errors.TokenMismatch();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
            wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
            fee
        );
        if (pool == address(0)) revert Errors.PoolNotFound();

        gasPCPoolByChainId[chainID] = pool;
        emit SetGasPCPool(chainID, pool, fee);
    }

    /**
     * @dev Fungible module updates the gas price oracle periodically.
     * @param chainID Chain ID
     * @param price New gas price
     */
    function setGasPrice(uint256 chainID, uint256 price) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        gasPriceByChainId[chainID] = price;
        emit SetGasPrice(chainID, price);
    }

    /**
     * @dev Setter for gasTokenPRC20ByChainId map.
     * @param chainID Chain ID
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(uint256 chainID, address prc20) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        if (prc20 == address(0)) revert Errors.ZeroAddress();
        gasTokenPRC20ByChainId[chainID] = prc20;
        emit SetGasToken(chainID, prc20);
    }

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        if (addr == address(0)) revert Errors.ZeroAddress();
        wPCContractAddress = addr;
        emit SetWPC(addr);
    }

    /**
     * @dev Default route for funding withdrawal gas with the chain's gas coin PRC20
     * @param payloadId Unique identifier for the withdrawal payload
     * @param dstChainId Destination chain ID
     * @param from Address to transfer tokens from
     * @param to Address to transfer tokens to
     * @param amount Amount of gas coin to transfer
     */
    function fundWithdrawGasWithgasToken(
        bytes32 payloadId,
        uint256 dstChainId,
        address from,
        address to,
        uint256 amount
    ) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        address gasToken = gasTokenPRC20ByChainId[dstChainId];
        if (gasToken == address(0)) revert Errors.ZeroAddress();

        // Pull from 'from' and send to 'to'
        SafeERC20.safeTransferFrom(IERC20(gasToken), from, to, amount);

        emit GasFundedWithGasToken(payloadId, dstChainId, gasToken, amount, from, to);
    }

    /**
     * @dev Alternate route for funding withdrawal gas by swapping the token being withdrawn
     * @param payloadId Unique identifier for the withdrawal payload
     * @param dstChainId Destination chain ID
     * @param tokenIn Token to swap from (e.g., the withdrawn asset)
     * @param amountIn Amount of tokenIn to use for gas funding
     * @param fee Uniswap V3 fee tier
     * @param minGasOut Minimum amount of gas coin to receive
     * @param from Address to transfer tokens from
     * @param to Address to receive gas coin
     * @param deadline Timestamp after which the transaction will revert
     */
    function fundWithdrawGasViaSwap(
        bytes32 payloadId,
        uint256 dstChainId,
        address tokenIn,
        uint256 amountIn,
        uint24 fee,
        uint256 minGasOut,
        address from,
        address to,
        uint256 deadline
    ) external nonReentrant {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert Errors.CallerIsNotFungibleModule();
        if (block.timestamp > deadline) revert Errors.DeadlineExpired();

        address gasToken = gasTokenPRC20ByChainId[dstChainId];
        if (gasToken == address(0)) revert Errors.ZeroAddress();

        // Pull tokenIn
        SafeERC20.safeTransferFrom(IERC20(tokenIn), from, address(this), amountIn);

        // Approve router
        SafeERC20.forceApprove(IERC20(tokenIn), uniswapV3SwapRouterAddress, amountIn);

        // Swap tokenIn -> gasToken via ExactInputSingle (single hop)
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: gasToken,
            fee: fee,
            recipient: to,
            deadline: deadline,
            amountIn: amountIn,
            amountOutMinimum: minGasOut,
            sqrtPriceLimitX96: 0
        });

        uint256 out = ISwapRouter(uniswapV3SwapRouterAddress).exactInputSingle(params);
        if (out < minGasOut) revert Errors.SlippageExceeded();

        // Clear approval
        SafeERC20.forceApprove(IERC20(tokenIn), uniswapV3SwapRouterAddress, 0);

        emit GasFundedViaSwap(payloadId, dstChainId, tokenIn, amountIn, gasToken, out, fee, from, to);
    }

    /**
     * @dev View helper to quote gas out for a single hop swap
     * @param tokenIn Input token address
     * @param tokenOut Output token address
     * @param fee Uniswap V3 fee tier
     * @param amountIn Amount of input token
     * @return amountOut Expected amount of output token
     */
    function quoteGasOutSingleHop(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn)
        external
        view
        returns (uint256 amountOut)
    {
        return IQuoter(uniswapV3QuoterAddress).quoteExactInputSingle(tokenIn, tokenOut, fee, amountIn, 0);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
