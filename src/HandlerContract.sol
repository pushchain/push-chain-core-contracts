// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./interfaces/IPRC20.sol";
import "./interfaces/IUniversalContract.sol";
import "./interfaces/IUniswapV3.sol";
import "./interfaces/IHandler.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @dev Custom errors for HandlerContract
 */
interface HandlerContractErrors {
    error CallerIsNotFungibleModule();
    error InvalidTarget();
    error CantBeIdenticalAddresses();
    error CantBeZeroAddress();
    error ZeroAddress();
    error PoolNotFound();
    error TokenMismatch();
    error SlippageExceeded();
    error DeadlineExpired();
}

/**
 * @dev The handler contract is called by the protocol to interact with the blockchain.
 * Also includes tools to make it easier to interact with Push Chain.
 * This is a Push Chain equivalent of ZetaChain's SystemContract.
 */
contract HandlerContract is HandlerContractErrors, IHandler, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Map to know the gas price of each chain given a chain id.
    mapping(uint256 => uint256) public gasPriceByChainId;
    
    /// @notice Map to know the PRC20 address of a token given a chain id, ex pETH, pBNB etc.
    mapping(uint256 => address) public gasTokenPRC20ByChainId;
    
    /// @notice Map to know Uniswap V3 pool of PC/PRC20 given a chain id.
    mapping(uint256 => address) public gasPCPoolByChainId;

    /// @notice Fungible address is always the same, it's on protocol level.
    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x735b14BB79463307AAcBED86DAf3322B1e6226aB;
    
    /// @notice Uniswap V3 addresses.
    address public immutable uniswapV3FactoryAddress;
    address public immutable uniswapV3SwapRouterAddress;
    address public immutable uniswapV3QuoterAddress;
    
    /// @notice Address of the wrapped PC to interact with Uniswap V3.
    address public wPCContractAddress;
    
    /// @notice Address of Push Chain Connector.
    address public pushConnectorEVMAddress;
    
    /**
     * @dev Only fungible module can deploy a handler contract.
     * @param wpc_ Address of the wrapped PC token
     * @param uniswapV3Factory_ Address of the Uniswap V3 factory
     * @param uniswapV3SwapRouter_ Address of the Uniswap V3 swap router
     * @param uniswapV3Quoter_ Address of the Uniswap V3 quoter
     */
    constructor(
        address wpc_,
        address uniswapV3Factory_,
        address uniswapV3SwapRouter_,
        address uniswapV3Quoter_
    ) {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        
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
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        if (target == UNIVERSAL_EXECUTOR_MODULE || target == address(this)) revert InvalidTarget();

        IPRC20(prc20).deposit(target, amount);
        IUniversalContract(target).onCrossChainCall(context, prc20, amount, message);
    }
    
    /**
     * @dev Set the gas PC pool for a chain
     * @param chainID Chain ID
     * @param gasToken Gas coin address
     * @param fee Uniswap V3 fee tier
     */
    function setGasPCPool(uint256 chainID, address gasToken, uint24 fee) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        // gasToken must equal gasTokenPRC20ByChainId[chainID]
        if (gasToken != gasTokenPRC20ByChainId[chainID]) revert TokenMismatch();

        address pool = IUniswapV3Factory(uniswapV3FactoryAddress).getPool(
            wPCContractAddress < gasToken ? wPCContractAddress : gasToken,
            wPCContractAddress < gasToken ? gasToken : wPCContractAddress,
            fee
        );
        if (pool == address(0)) revert PoolNotFound();

        gasPCPoolByChainId[chainID] = pool;
        emit SetGasPCPool(chainID, pool, fee);
    }
    
    /**
     * @dev Fungible module updates the gas price oracle periodically.
     * @param chainID Chain ID
     * @param price New gas price
     */
    function setGasPrice(uint256 chainID, uint256 price) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        gasPriceByChainId[chainID] = price;
        emit SetGasPrice(chainID, price);
    }

    /**
     * @dev Setter for gasTokenPRC20ByChainId map.
     * @param chainID Chain ID
     * @param prc20 PRC20 address
     */
    function setGasTokenPRC20(uint256 chainID, address prc20) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        if (prc20 == address(0)) revert ZeroAddress();
        gasTokenPRC20ByChainId[chainID] = prc20;
        emit SetGasToken(chainID, prc20);
    }

    /**
     * @dev Setter for wrapped PC address.
     * @param addr WPC new address
     */
    function setWPCContractAddress(address addr) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        if (addr == address(0)) revert ZeroAddress();
        wPCContractAddress = addr;
        emit SetWPC(addr);
    }

    /**
     * @dev Setter for pushConnector EVM Address
     * @param addr Push connector new address
     */
    function setConnectorEVMAddress(address addr) external {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        if (addr == address(0)) revert ZeroAddress();
        pushConnectorEVMAddress = addr;
        emit SetConnectorEVM(addr);
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
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        address gasToken = gasTokenPRC20ByChainId[dstChainId];
        if (gasToken == address(0)) revert ZeroAddress();

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
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) revert CallerIsNotFungibleModule();
        if (block.timestamp > deadline) revert DeadlineExpired();

        address gasToken = gasTokenPRC20ByChainId[dstChainId];
        if (gasToken == address(0)) revert ZeroAddress();

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
        if (out < minGasOut) revert SlippageExceeded();

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
    function quoteGasOutSingleHop(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountIn
    ) external view returns (uint256 amountOut) {
        return IQuoter(uniswapV3QuoterAddress).quoteExactInputSingle(
            tokenIn,
            tokenOut,
            fee,
            amountIn,
            0
        );
    }
}
