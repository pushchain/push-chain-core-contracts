// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IPRC20} from "./interfaces/IPRC20.sol";
import {IUniversalCore} from "./interfaces/IUniversalCore.sol";
import {IUniswapV3Factory, ISwapRouter} from "./interfaces/uniswapv3/IUniswapV3.sol";
import {IWPC} from "./interfaces/IWPC.sol";
import {UniversalCoreErrors, CommonErrors} from "./libraries/Errors.sol";

/**
 * @title   UniversalCore
 * @notice  The UniversalCore acts as the core contract for all functionalities
 *          needed by the interoperability feature of Push Chain.
 * @dev     The UniversalCore primarily handles the following functionalities:
 *            - Generation of supported PRC-20 tokens, and transferring it to accurate recipients.
 *            - Setting up the gas tokens for each chain.
 *            - Setting up the gas price for each chain.
 *            - Maintaining a registry of Uniswap V3 pools for each token pair.
 * @dev     All imperative functionalities are handled by the Universal Executor Module.
 */
contract UniversalCore is
    IUniversalCore,
    Initializable,
    ReentrancyGuardUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    // =========================
    //    UC: STATE VARIABLES
    // =========================

    // -- Protocol constants & roles --

    address public immutable UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // -- Uniswap V3 fee tiers --
    uint24 public constant FEE_TIER_LOWEST = 100;
    uint24 public constant FEE_TIER_LOW = 500;
    uint24 public constant FEE_TIER_MEDIUM = 3000;
    uint24 public constant FEE_TIER_HIGH = 10000;

    // -- Protocol addresses --
    address public universalGatewayPC;
    address public WPC;

    // -- Chain configuration --

    mapping(string => uint256) public gasPriceByChainNamespace;
    mapping(string => address) public gasTokenPRC20ByChainNamespace;
    mapping(string => uint256) public baseGasLimitByChainNamespace;
    mapping(string => uint256) public rescueFundsGasLimitByChainNamespace;
    mapping(string => uint256) public chainHeightByChainNamespace;
    mapping(string => uint256) public timestampObservedAtByChainNamespace;

    /// @notice Maximum acceptable age (seconds) of `timestampObservedAtByChainNamespace`
    ///         before gas fee quotes for that chain are rejected as stale.
    /// @dev    `0` disables the check for that chain (opt-in). Set per chain by
    ///         MANAGER_ROLE via `setMaxStalenessByChain`.
    mapping(string => uint256) public maxStalenessByChainNamespace;

    // -- Token configuration --

    mapping(address => uint256) public protocolFeeByToken;

    // -- Uniswap and AMM specific states --

    address public uniswapV3Factory;
    address public uniswapV3SwapRouter;
    /// @notice Stored gas PC pool per chain — informational only for off-chain consumers.
    /// @dev    Not used in runtime swap logic. Pool resolution is dynamic via uniswapV3Factory.
    mapping(string => address) public gasPCPoolByChainNamespace;
    mapping(address => bool) public isAutoSwapSupported;
    mapping(address => uint24) public defaultFeeTier;
    uint256 public defaultDeadlineMins;

    // =========================
    //    UC: MODIFIERS
    // =========================

    modifier onlyUEModule() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) {
            revert UniversalCoreErrors.CallerIsNotUEModule();
        }
        _;
    }

    modifier onlyGatewayPC() {
        if (msg.sender != universalGatewayPC) {
            revert UniversalCoreErrors.CallerIsNotGatewayPC();
        }
        _;
    }

    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert CommonErrors.InvalidOwner();
        }
        _;
    }

    // =========================
    //    UC: CONSTRUCTOR
    // =========================

    constructor() {
        _disableInitializers();
    }

    /// @dev                             Initializer function for the upgradeable contract.
    /// @param wpc_                      Address of the wrapped PC token
    /// @param uniswapV3Factory_         Address of the Uniswap V3 factory
    /// @param uniswapV3SwapRouter_      Address of the Uniswap V3 swap router
    function initialize(
        address wpc_,
        address uniswapV3Factory_,
        address uniswapV3SwapRouter_,
        address initialPauser_
    ) public virtual initializer {
        if (initialPauser_ == address(0)) revert CommonErrors.ZeroAddress();
        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, initialPauser_);

        emit PauserRoleGranted(initialPauser_);

        WPC = wpc_;
        uniswapV3Factory = uniswapV3Factory_;
        uniswapV3SwapRouter = uniswapV3SwapRouter_;
        defaultDeadlineMins = 20;
    }

    // =========================
    //    UC_1: UE MODULE ACTIONS
    // =========================

    /// @inheritdoc IUniversalCore
    function depositPRC20Token(address prc20, uint256 amount, address recipient) external onlyUEModule whenNotPaused nonReentrant {
        _validateParams(prc20, amount, recipient);
        if (!IPRC20(prc20).deposit(recipient, amount)) revert UniversalCoreErrors.PRC20OperationFailed();
    }

    /// @inheritdoc IUniversalCore
    function depositPRC20WithAutoSwap(
        address prc20,
        uint256 amount,
        address recipient,
        uint24 fee,
        uint256 minPCOut,
        uint256 deadline
    ) external onlyUEModule whenNotPaused nonReentrant {
        _validateParams(prc20, amount, recipient);

        (uint256 pcOut, uint24 resolvedFee) = _autoSwap(prc20, amount, recipient, fee, minPCOut, deadline);

        emit DepositPRC20WithAutoSwap(prc20, amount, WPC, pcOut, resolvedFee, recipient);
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
        _validateParams(gasToken, amount, recipient);

        uint256 pcOut;

        if (!withSwap) {
            if (!IPRC20(gasToken).deposit(recipient, amount)) revert UniversalCoreErrors.PRC20OperationFailed();
        } else {
            if (minPCOut == 0) {
                revert UniversalCoreErrors.MinPCOutRequired();
            }
            (pcOut,) = _autoSwap(gasToken, amount, recipient, fee, minPCOut, 0);
        }

        emit RefundUnusedGas(gasToken, amount, recipient, withSwap, pcOut);
    }

    // =========================
    //    UC_2: GATEWAY ACTIONS
    // =========================

    /// @inheritdoc IUniversalCore
    function swapAndBurnGas(address gasToken, uint24 fee, uint256 gasFee, uint256 deadline, address caller)
        external
        payable
        onlyGatewayPC
        whenNotPaused
        nonReentrant
        returns (uint256 gasTokenOut, uint256 refund)
    {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();
        if (caller == address(0)) revert CommonErrors.ZeroAddress();
        if (msg.value == 0) revert CommonErrors.ZeroAmount();
        if (gasFee == 0) revert CommonErrors.ZeroAmount();

        if (fee == 0) {
            fee = defaultFeeTier[gasToken];
            if (fee == 0) revert UniversalCoreErrors.InvalidFeeTier();
        }

        if (deadline == 0) {
            deadline = block.timestamp + (defaultDeadlineMins * 1 minutes);
        }
        if (block.timestamp > deadline) revert CommonErrors.DeadlineExpired();

        address pool = IUniswapV3Factory(uniswapV3Factory)
            .getPool(WPC < gasToken ? WPC : gasToken, WPC < gasToken ? gasToken : WPC, fee);
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        IWPC(WPC).deposit{value: msg.value}();

        IERC20(WPC).forceApprove(uniswapV3SwapRouter, msg.value);

        ISwapRouter.ExactOutputSingleParams memory params = ISwapRouter.ExactOutputSingleParams({
            tokenIn: WPC,
            tokenOut: gasToken,
            fee: fee,
            recipient: address(this),
            deadline: deadline,
            amountOut: gasFee,
            amountInMaximum: msg.value,
            sqrtPriceLimitX96: 0
        });

        uint256 amountInUsed = ISwapRouter(uniswapV3SwapRouter).exactOutputSingle(params);
        IERC20(WPC).forceApprove(uniswapV3SwapRouter, 0);

        if (!IPRC20(gasToken).burn(gasFee)) revert UniversalCoreErrors.PRC20OperationFailed();

        gasTokenOut = gasFee;
        refund = msg.value - amountInUsed;
        if (refund > 0) {
            IWPC(WPC).withdraw(refund);
            (bool ok,) = caller.call{value: refund}("");
            if (!ok) revert CommonErrors.TransferFailed();
        }

        emit SwapAndBurnGas(gasToken, amountInUsed, gasFee, fee, caller);
    }

    // =========================
    //    UC_3: PUBLIC GETTERS
    // =========================

    /// @inheritdoc IUniversalCore
    function getOutboundTxGasAndFees(address _prc20, uint256 gasLimitWithBaseLimit)
        public
        view
        returns (address gasToken, uint256 gasFee, uint256 protocolFee, uint256 gasPrice, string memory chainNamespace)
    {
        chainNamespace = IPRC20(_prc20).SOURCE_CHAIN_NAMESPACE();
        uint256 baseLimit = baseGasLimitByChainNamespace[chainNamespace];
        if (baseLimit == 0) revert UniversalCoreErrors.ZeroBaseGasLimit();

        if (gasLimitWithBaseLimit == 0) {
            gasLimitWithBaseLimit = baseLimit;
        } else if (gasLimitWithBaseLimit < baseLimit) {
            revert UniversalCoreErrors.GasLimitBelowBase(gasLimitWithBaseLimit, baseLimit);
        }

        gasToken = gasTokenPRC20ByChainNamespace[chainNamespace];
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        gasPrice = gasPriceByChainNamespace[chainNamespace];
        if (gasPrice == 0) revert UniversalCoreErrors.ZeroGasPrice();

        _validateGasDataFreshness(chainNamespace);

        gasFee = gasPrice * gasLimitWithBaseLimit;
        protocolFee = protocolFeeByToken[_prc20];
    }

    /// @inheritdoc IUniversalCore
    function getRescueFundsGasLimit(address _prc20)
        public
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 rescueGasLimit,
            uint256 gasPrice,
            string memory chainNamespace
        )
    {
        chainNamespace = IPRC20(_prc20).SOURCE_CHAIN_NAMESPACE();

        rescueGasLimit = rescueFundsGasLimitByChainNamespace[chainNamespace];
        if (rescueGasLimit == 0) {
            revert UniversalCoreErrors.ZeroRescueGasLimit();
        }

        gasToken = gasTokenPRC20ByChainNamespace[chainNamespace];
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        gasPrice = gasPriceByChainNamespace[chainNamespace];
        if (gasPrice == 0) revert UniversalCoreErrors.ZeroGasPrice();

        _validateGasDataFreshness(chainNamespace);

        gasFee = gasPrice * rescueGasLimit;
    }

    // =========================
    //    UC_4: MANAGER ACTIONS
    // =========================

    /// @notice              Set protocol fee (in native PC) for a token.
    /// @param token         Token address
    /// @param fee           Protocol fee amount in native PC
    function setProtocolFeeByToken(address token, uint256 fee) external onlyRole(MANAGER_ROLE) {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        protocolFeeByToken[token] = fee;
        emit SetProtocolFeeByToken(token, fee);
    }

    /// @notice                  Set the gas PC pool for a chain (informational — not enforced at runtime).
    /// @dev                     The stored pool is for off-chain observability only. Runtime swap flows
    ///                          (swapAndBurnGas, _autoSwap) resolve pools dynamically from the factory.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param gasToken          Gas coin address
    /// @param fee               Uniswap V3 fee tier
    function setGasPCPool(string memory chainNamespace, address gasToken, uint24 fee) external onlyRole(MANAGER_ROLE) {
        if (gasToken == address(0)) revert CommonErrors.ZeroAddress();

        address pool = IUniswapV3Factory(uniswapV3Factory)
            .getPool(WPC < gasToken ? WPC : gasToken, WPC < gasToken ? gasToken : WPC, fee);
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        gasPCPoolByChainNamespace[chainNamespace] = pool;
        emit SetGasPCPool(chainNamespace, pool, fee);
    }

    /// @notice                  Set gas price, chain height, and observation timestamp for a chain.
    /// @dev                     `observedAt` is set to `block.timestamp` of the Push Chain block
    ///                          in which this call is included.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param price             Gas price on the external chain
    /// @param chainHeight       Block height observed on the external chain
    function setChainMeta(string memory chainNamespace, uint256 price, uint256 chainHeight)
        external
        onlyUEModule
    {
        if (price == 0) revert UniversalCoreErrors.ZeroGasPrice();
        gasPriceByChainNamespace[chainNamespace] = price;
        chainHeightByChainNamespace[chainNamespace] = chainHeight;
        timestampObservedAtByChainNamespace[chainNamespace] = block.timestamp;
        emit SetChainMeta(chainNamespace, price, chainHeight, block.timestamp);
    }

    /// @notice                  Setter for gasTokenPRC20ByChainNamespace map.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param prc20             PRC20 address
    function setGasTokenPRC20(string memory chainNamespace, address prc20) external onlyRole(MANAGER_ROLE) {
        if (prc20 == address(0)) revert CommonErrors.ZeroAddress();
        gasTokenPRC20ByChainNamespace[chainNamespace] = prc20;
        gasPriceByChainNamespace[chainNamespace] = 0;
        emit SetGasToken(chainNamespace, prc20);
    }

    // =========================
    //    UC_5: ADMIN ACTIONS
    // =========================

    /// @notice          Set auto-swap support for a token.
    /// @param token     Token address
    /// @param supported Whether the token supports auto-swap
    function setAutoSwapSupported(address token, bool supported) external onlyAdmin {
        isAutoSwapSupported[token] = supported;
        emit SetAutoSwapSupported(token, supported);
    }

    /// @notice      Set the wrapped PC address.
    /// @param addr  WPC new address
    function setWPC(address addr) external onlyAdmin {
        if (addr == address(0)) revert CommonErrors.ZeroAddress();
        address oldAddr = WPC;
        WPC = addr;
        emit SetWPC(oldAddr, addr);
    }

    /// @notice      Set the UniversalGatewayPC address.
    /// @param addr  UniversalGatewayPC address
    function setUniversalGatewayPC(address addr) external onlyAdmin {
        if (addr == address(0)) revert CommonErrors.ZeroAddress();
        address oldAddr = universalGatewayPC;
        universalGatewayPC = addr;
        emit SetUniversalGatewayPC(oldAddr, addr);
    }

    /// @notice             Setter for Uniswap V3 addresses.
    /// @param factory      Uniswap V3 Factory address
    /// @param swapRouter   Uniswap V3 SwapRouter address
    function setUniswapV3Addresses(address factory, address swapRouter) external onlyAdmin {
        if (factory == address(0) || swapRouter == address(0)) {
            revert CommonErrors.ZeroAddress();
        }
        uniswapV3Factory = factory;
        uniswapV3SwapRouter = swapRouter;
        emit SetUniswapV3Addresses(factory, swapRouter);
    }

    /// @notice          Set default fee tier for a token.
    /// @param token     Token address
    /// @param feeTier   Fee tier (500, 3000, 10000)
    function setDefaultFeeTier(address token, uint24 feeTier) external onlyAdmin {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        if (feeTier != FEE_TIER_LOWEST && feeTier != FEE_TIER_LOW && feeTier != FEE_TIER_MEDIUM && feeTier != FEE_TIER_HIGH) {
            revert UniversalCoreErrors.InvalidFeeTier();
        }
        defaultFeeTier[token] = feeTier;
        emit SetDefaultFeeTier(token, feeTier);
    }

    /// @notice               Set default deadline in minutes.
    /// @param minutesValue   Default deadline in minutes
    function setDefaultDeadlineMins(uint256 minutesValue) external onlyAdmin {
        defaultDeadlineMins = minutesValue;
        emit SetDefaultDeadlineMins(minutesValue);
    }

    /// @notice                  Set base gas limit for a specific chain.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param gasLimit          Base gas limit for the chain
    function setBaseGasLimitByChain(string memory chainNamespace, uint256 gasLimit) external onlyRole(MANAGER_ROLE) {
        baseGasLimitByChainNamespace[chainNamespace] = gasLimit;
        emit SetBaseGasLimitByChain(chainNamespace, gasLimit);
    }

    /// @notice                  Set rescue funds gas limit for a specific chain.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param gasLimit          Rescue funds gas limit for the chain
    function setRescueFundsGasLimitByChain(string memory chainNamespace, uint256 gasLimit)
        external
        onlyRole(MANAGER_ROLE)
    {
        rescueFundsGasLimitByChainNamespace[chainNamespace] = gasLimit;
        emit SetRescueFundsGasLimitByChain(chainNamespace, gasLimit);
    }

    /// @notice                  Set the maximum acceptable age (seconds) of gas data for a chain.
    /// @dev                     A value of `0` disables the staleness check for that chain (opt-in).
    ///                          When set, `getOutboundTxGasAndFees` and `getRescueFundsGasLimit`
    ///                          revert with `StaleGasData` if the chain's observed timestamp is
    ///                          older than `block.timestamp - maxStaleness`.
    /// @param chainNamespace    Chain Namespace (e.g. "eip155:1" for Ethereum Mainnet)
    /// @param maxStaleness      Maximum acceptable age of gas data in seconds (0 disables)
    function setMaxStalenessByChain(string memory chainNamespace, uint256 maxStaleness)
        external
        onlyRole(MANAGER_ROLE)
    {
        maxStalenessByChainNamespace[chainNamespace] = maxStaleness;
        emit SetMaxStalenessByChain(chainNamespace, maxStaleness);
    }

    /// @notice Pause the contract - stops all deposit functions. Only callable by PAUSER_ROLE.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract - resumes all deposit functions. Only callable by PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice              Grant PAUSER_ROLE to a new address. Only callable by admin.
    /// @param newPauser     Address to grant pauser role to
    function setPauserRole(address newPauser) external onlyAdmin {
        if (newPauser == address(0)) revert CommonErrors.ZeroAddress();
        _grantRole(PAUSER_ROLE, newPauser);
        emit PauserRoleGranted(newPauser);
    }

    /// @notice              Rescue native PC stuck in the contract. Only callable by admin.
    /// @param to            Recipient address for the rescued PC
    /// @param amount        Amount of native PC to rescue
    function rescueNativePC(address payable to, uint256 amount) external onlyAdmin {
        if (to == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();
        if (amount > address(this).balance) revert CommonErrors.InsufficientBalance();
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();
        emit RescueNativePC(to, amount);
    }

    // =========================
    //    UC_6: PRIVATE HELPERS
    // =========================

    /// @dev Shared input validation for deposit/refund functions.
    /// @param token      Token address to validate
    /// @param amount     Amount to validate (must be > 0)
    /// @param recipient  Recipient address to validate
    function _validateParams(address token, uint256 amount, address recipient) private view {
        if (token == address(0)) revert CommonErrors.ZeroAddress();
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
        if (recipient == UNIVERSAL_EXECUTOR_MODULE || recipient == address(this)) {
            revert UniversalCoreErrors.InvalidTarget();
        }
        if (amount == 0) revert CommonErrors.ZeroAmount();
    }

    /// @dev Enforces that gas data for `chainNamespace` is within the configured freshness
    ///      window. No-op when `maxStalenessByChainNamespace[chainNamespace]` is `0`
    ///      (check disabled). Reverts with `StaleGasData` when the data is older than
    ///      the configured max age, carrying the observed timestamp, current timestamp,
    ///      and max age in the revert data.
    /// @param chainNamespace   Chain namespace whose freshness is being validated
    function _validateGasDataFreshness(string memory chainNamespace) private view {
        uint256 maxAge = maxStalenessByChainNamespace[chainNamespace];
        if (maxAge == 0) return;
        uint256 observedAt = timestampObservedAtByChainNamespace[chainNamespace];
        if (block.timestamp > observedAt + maxAge) {
            revert UniversalCoreErrors.StaleGasData(observedAt, block.timestamp, maxAge);
        }
    }

    /// @dev Swap PRC20 to native PC via Uniswap V3 and send to recipient.
    /// @param prc20      PRC20 token address to swap
    /// @param amount     Amount of PRC20 to swap
    /// @param recipient  Address to receive the swapped native PC
    /// @param fee        Uniswap V3 fee tier (0 = use default)
    /// @param minPCOut   Minimum PC output expected
    /// @param deadline   Swap deadline (0 = use default)
    /// @return pcOut     Amount of native PC sent to recipient
    /// @return resolvedFee  Actual fee tier used for the swap
    function _autoSwap(address prc20, uint256 amount, address recipient, uint24 fee, uint256 minPCOut, uint256 deadline)
        private
        returns (uint256 pcOut, uint24 resolvedFee)
    {
        if (!isAutoSwapSupported[prc20]) {
            revert UniversalCoreErrors.AutoSwapNotSupported();
        }

        resolvedFee = fee;
        if (resolvedFee == 0) {
            resolvedFee = defaultFeeTier[prc20];
            if (resolvedFee == 0) revert UniversalCoreErrors.InvalidFeeTier();
        }

        if (deadline == 0) {
            deadline = block.timestamp + (defaultDeadlineMins * 1 minutes);
        }
        if (block.timestamp > deadline) revert CommonErrors.DeadlineExpired();

        address pool = IUniswapV3Factory(uniswapV3Factory)
            .getPool(prc20 < WPC ? prc20 : WPC, prc20 < WPC ? WPC : prc20, resolvedFee);
        if (pool == address(0)) revert UniversalCoreErrors.PoolNotFound();

        if (minPCOut == 0) revert CommonErrors.ZeroAmount();

        if (!IPRC20(prc20).deposit(address(this), amount)) revert UniversalCoreErrors.PRC20OperationFailed();
        IERC20(prc20).forceApprove(uniswapV3SwapRouter, amount);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: prc20,
            tokenOut: WPC,
            fee: resolvedFee,
            recipient: address(this),
            deadline: deadline,
            amountIn: amount,
            amountOutMinimum: minPCOut,
            sqrtPriceLimitX96: 0
        });

        pcOut = ISwapRouter(uniswapV3SwapRouter).exactInputSingle(params);
        if (pcOut < minPCOut) revert UniversalCoreErrors.SlippageExceeded();

        IERC20(prc20).forceApprove(uniswapV3SwapRouter, 0);

        IWPC(WPC).withdraw(pcOut);
        (bool ok,) = recipient.call{value: pcOut}("");
        if (!ok) revert CommonErrors.TransferFailed();
    }

    // =========================
    //    UC: RECEIVE
    // =========================

    /// @notice Accept native PC transfers (e.g., from WPC withdraw).
    receive() external payable {}
}
