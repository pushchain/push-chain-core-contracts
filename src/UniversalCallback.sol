// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {
    AccessControlDefaultAdminRulesUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {
    ReadSpec,
    PendingRead,
    RequestStatus,
    MIN_CONFIRMATIONS_FLOOR,
    MAX_CALLBACK_GAS_LIMIT
} from "./libraries/ReadTypes.sol";
import {UniversalCallbackErrors, CommonErrors} from "./libraries/Errors.sol";
import {IUniversalCore} from "./interfaces/IUniversalCore.sol";
import {IUniversalCallback} from "./interfaces/IUniversalCallback.sol";

contract UniversalCallback is
    IUniversalCallback,
    Initializable,
    ReentrancyGuardUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable
{
    address public immutable UNIVERSAL_CALLBACK_MODULE = 0x07a0258D367A4A4cd9d6E4b7eEE8E7eF491CC519;

    IUniversalCore internal _universalCore;
    address internal _vaultPC;

    bytes32 public constant UVCALLBACK_ADMIN_ROLE = keccak256("UVCALLBACK_ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Lifecycle state per request. Persists after `_pending` is deleted,
    ///         which is what makes terminal states replay-proof.
    mapping(uint256 => RequestStatus) internal _status;
    mapping(uint256 => PendingRead) private _pending;
    uint256 private _requestNonce;
    mapping(string => mapping(string => bool)) public blockedDomains;

    /// @notice Total callback budget held for requests that have not settled yet.
    ///         Escrowed funds are user-owned and are excluded from what
    ///         `rescueNativePC` may take.
    /// @dev    Append-only storage: new variables MUST go after this block.
    uint256 public totalEscrowed;

    constructor() {
        _disableInitializers();
    }

    function initialize(address universalCore_, address vaultPC_, address defaultAdmin) external initializer {
        if (universalCore_ == address(0) || vaultPC_ == address(0) || defaultAdmin == address(0)) {
            revert UniversalCallbackErrors.ZeroAddressInit();
        }
        __ReentrancyGuard_init();
        __AccessControlDefaultAdminRules_init(1 days, defaultAdmin);
        __Pausable_init();

        _grantRole(UVCALLBACK_ADMIN_ROLE, defaultAdmin);
        _grantRole(PAUSER_ROLE, defaultAdmin);

        _universalCore = IUniversalCore(universalCore_);
        _vaultPC = vaultPC_;
    }

    modifier onlyUCallbackModule() {
        if (msg.sender != UNIVERSAL_CALLBACK_MODULE) {
            revert UniversalCallbackErrors.CallerIsNotUCallbackModule();
        }
        _;
    }

    modifier onlyUvCallbackAdmin() {
        if (!hasRole(UVCALLBACK_ADMIN_ROLE, msg.sender)) {
            revert UniversalCallbackErrors.CallerIsNotAdmin();
        }
        _;
    }

    modifier onlyPauser() {
        if (!hasRole(PAUSER_ROLE, msg.sender)) {
            revert UniversalCallbackErrors.UnauthorizedCaller();
        }
        _;
    }

    function requestExternalReadSelf(ReadSpec calldata spec, bytes4 callbackSelector, uint64 callbackGasLimit)
        external
        payable
        override
        whenNotPaused
        nonReentrant
        returns (uint256 requestId)
    {
        if (
            bytes(spec.account.chainNamespace).length == 0 || bytes(spec.account.chainId).length == 0
                || spec.account.owner.length == 0
        ) {
            revert UniversalCallbackErrors.InvalidAccountId();
        }
        if (spec.query.length == 0) {
            revert UniversalCallbackErrors.EmptyQuery();
        }
        if (spec.minConfirmations < MIN_CONFIRMATIONS_FLOOR) {
            revert UniversalCallbackErrors.InvalidMinConfirmations();
        }
        if (blockedDomains[spec.account.chainNamespace][spec.account.chainId]) {
            revert UniversalCallbackErrors.DomainBlocked(spec.account.chainNamespace, spec.account.chainId);
        }
        if (
            spec.blockNumber == 0
                || spec.blockNumber > _universalCore.chainHeightByChainNamespace(spec.account.chainNamespace)
        ) {
            revert UniversalCallbackErrors.InvalidBlockNumber();
        }
        if (spec.expiryPushChainHeight <= block.number) {
            revert UniversalCallbackErrors.InvalidExpiryHeight();
        }
        if (spec.revertRecipient == address(0)) {
            revert UniversalCallbackErrors.ZeroRevertRecipient();
        }
        if (callbackGasLimit == 0) {
            revert UniversalCallbackErrors.ZeroCallbackGasLimit();
        }
        if (callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) {
            revert UniversalCallbackErrors.CallbackGasLimitExceeded(callbackGasLimit, MAX_CALLBACK_GAS_LIMIT);
        }

        uint256 protocolFee =
            _universalCore.readBaseFeeByChainNamespace(spec.account.chainNamespace, spec.account.chainId);
        if (msg.value < protocolFee) {
            revert UniversalCallbackErrors.InsufficientFee(msg.value, protocolFee);
        }
        if (msg.value > spec.maxFee) {
            revert UniversalCallbackErrors.ExcessiveFee(msg.value, spec.maxFee);
        }

        requestId = uint256(
            keccak256(
                abi.encode(block.chainid, block.number, address(this), keccak256(abi.encode(spec)), _requestNonce++)
            )
        );

        // note: A budget of zero is legal: the caller paid exactly the protocol fee and funded no callback execution.
        uint256 callbackBudget = msg.value - protocolFee;

        _status[requestId] = RequestStatus.PENDING;
        _pending[requestId] = PendingRead({
            callbackTarget: msg.sender,
            callbackSelector: callbackSelector,
            callbackGasLimit: callbackGasLimit,
            originalFunder: msg.sender,
            expiryHeight: spec.expiryPushChainHeight,
            revertRecipient: spec.revertRecipient,
            callbackBudget: callbackBudget
        });

        totalEscrowed += callbackBudget;

        emit ReadRequested(
            requestId, spec, msg.sender, msg.sender, callbackGasLimit, msg.value, protocolFee, callbackBudget
        );

        if (protocolFee > 0) {
            _payProtocolFee(requestId, protocolFee);
        }
    }

    function fulfillExternalCallback(
        uint256 requestId,
        bytes calldata resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    ) external override onlyUCallbackModule nonReentrant {
        _requireStatus(requestId, RequestStatus.PENDING);

        PendingRead memory p = _pending[requestId];
        if (p.callbackTarget == address(0)) {
            revert UniversalCallbackErrors.InvalidCallbackTarget();
        }

        _status[requestId] = RequestStatus.EXECUTED;

        (bool success, bytes memory reason) = p.callbackTarget.call{gas: p.callbackGasLimit}(
            abi.encodeWithSelector(p.callbackSelector, requestId, resultData)
        );

        if (success) {
            emit ReadFulfilled(requestId, resultData, observedBlockHeight, observedBlockHash);
        } else {
            emit CallbackFailed(requestId, reason);
        }
    }

    /// @notice             Settle an executed request against the gas it consumed.
    /// @dev                Performs NO burn and moves no value. On return the
    ///                     contract is over-collateralised by exactly `burned`,
    ///                     which is what the caller must then burn. The caller MUST
    ///                     burn the returned value rather than its own measurement
    ///                     -- recomputing bypasses the budget clamp -- and MUST NOT
    ///                     call anything else here first, or `rescueNativePC` could
    ///                     take the slack.
    ///                     Not `whenNotPaused`: a pause must never trap escrow.
    /// @param requestId    Request to settle
    /// @param gasBurned    Raw gas cost measured by the module
    /// @return burned      `gasBurned` clamped to the request's callback budget
    function reportCallbackGas(uint256 requestId, uint256 gasBurned)
        external
        override
        onlyUCallbackModule
        nonReentrant
        returns (uint256 burned)
    {
        _requireStatus(requestId, RequestStatus.EXECUTED);

        PendingRead memory p = _pending[requestId];

        burned = gasBurned > p.callbackBudget ? p.callbackBudget : gasBurned;
        uint256 refund = p.callbackBudget - burned;

        _status[requestId] = RequestStatus.SETTLED;
        delete _pending[requestId];
        totalEscrowed -= p.callbackBudget;

        if (refund > 0) {
            _refund(requestId, p.revertRecipient, refund);
        }

        emit CallbackGasReported(requestId, gasBurned, burned, refund);
    }

    function expireExternalRead(uint256 requestId) external override onlyUCallbackModule nonReentrant {
        _requireStatus(requestId, RequestStatus.PENDING);

        PendingRead memory p = _pending[requestId];
        if (block.number < p.expiryHeight) {
            revert UniversalCallbackErrors.RequestNotYetExpired();
        }

        _status[requestId] = RequestStatus.EXPIRED;
        delete _pending[requestId];
        totalEscrowed -= p.callbackBudget;

        if (p.callbackBudget > 0) {
            _refund(requestId, p.revertRecipient, p.callbackBudget);
        }

        emit RequestExpired(requestId, p.revertRecipient, p.callbackBudget);
    }

    /// @dev                Reverts unless the request is in exactly `expected`.
    ///                     A single-value check is safer than disjunctions, and
    ///                     the error carries both states for debugging.
    function _requireStatus(uint256 requestId, RequestStatus expected) private view {
        RequestStatus actual = _status[requestId];
        if (actual != expected) {
            revert UniversalCallbackErrors.InvalidRequestStatus(requestId, uint8(actual), uint8(expected));
        }
    }

    /// @dev                Pushes the unspent budget to the request's revert
    ///                     recipient. Callers MUST have already released the
    ///                     corresponding escrow.
    ///                     A failed transfer is deliberately NOT fatal: reverting
    ///                     would leave the request stuck in EXECUTED with its
    ///                     escrow locked forever, so a recipient that rejects
    ///                     payment forfeits its own refund instead of wedging
    ///                     settlement. The stranded PC stays recoverable via
    ///                     `rescueNativePC`.
    function _refund(uint256 requestId, address recipient, uint256 amount) private {
        (bool ok,) = recipient.call{value: amount}("");
        if (ok) {
            emit RefundSent(requestId, recipient, amount);
        } else {
            emit RefundFailed(requestId, recipient, amount);
        }
    }

    /// @dev                Pushes the protocol fee to the vault at request time.
    ///                     Reverts loudly on failure: VaultPC accepts plain
    ///                     transfers unconditionally, so a failure means the vault
    ///                     is misconfigured. Failing here aborts the whole request
    ///                     before anything is escrowed, which is the safe outcome.
    ///                     Any future vault MUST keep accepting plain transfers.
    /// @param requestId    Request the fee belongs to
    /// @param amount       Protocol fee amount
    function _payProtocolFee(uint256 requestId, uint256 amount) private {
        address vault = _vaultPC;
        (bool ok,) = vault.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();
        emit ProtocolFeeDistributed(requestId, vault, amount);
    }

    /// @notice             Recover unattributed native PC -- funds sent here by
    ///                     accident or force-fed via `selfdestruct`/coinbase.
    /// @dev                Protocol fees never accumulate here (they are forwarded
    ///                     to VaultPC at request time), so this is a rescue hatch
    ///                     rather than a fee sweep. Escrowed budgets are
    ///                     user-owned and are excluded from the cap; refunds that a
    ///                     recipient rejected are recoverable through here.
    ///                     MUST NOT be called between `reportCallbackGas` and the
    ///                     module's burn -- the slack in that window belongs to the
    ///                     pending burn.
    /// @param recipient    Address to receive the rescued PC
    /// @param amount       Amount to rescue, capped at the unattributed balance
    function rescueNativePC(address payable recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        uint256 available = address(this).balance - totalEscrowed;
        if (amount > available) {
            revert UniversalCallbackErrors.InsufficientContractBalance(amount, available);
        }
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();
        emit NativePCRescued(recipient, amount);
    }

    /// @notice     Exact minimum `msg.value` for a request on this domain. Callback
    ///             execution is not priced here -- anything sent above this becomes
    ///             the callback budget.
    function estimateFee(string calldata chainNamespace, string calldata chainId)
        external
        view
        override
        returns (uint256)
    {
        return _universalCore.readBaseFeeByChainNamespace(chainNamespace, chainId);
    }

    /// @notice     True once a request can never execute again. Note this is true
    ///             in EXECUTED, before the gas report has moved any money.
    function isFulfilled(uint256 requestId) external view override returns (bool) {
        RequestStatus s = _status[requestId];
        return s == RequestStatus.EXECUTED || s == RequestStatus.SETTLED || s == RequestStatus.EXPIRED;
    }

    function statusOf(uint256 requestId) external view override returns (RequestStatus) {
        return _status[requestId];
    }

    /// @notice     Live request record. Returns a zeroed struct once a request is
    ///             SETTLED or EXPIRED -- use `statusOf` to distinguish "terminal"
    ///             from "never existed".
    function getPendingRead(uint256 requestId) external view returns (PendingRead memory) {
        return _pending[requestId];
    }

    function updateBlockedDomain(string calldata chainNamespace, string calldata chainId, bool blocked)
        external
        onlyUvCallbackAdmin
    {
        blockedDomains[chainNamespace][chainId] = blocked;
        emit DomainUpdated(chainNamespace, chainId, blocked);
    }

    function isDomainBlocked(string calldata chainNamespace, string calldata chainId) external view returns (bool) {
        return blockedDomains[chainNamespace][chainId];
    }

    function pause() external onlyPauser {
        _pause();
    }

    function unpause() external onlyPauser {
        _unpause();
    }

    function universalCore() external view returns (IUniversalCore) {
        return _universalCore;
    }

    function vaultPC() external view returns (address) {
        return _vaultPC;
    }

    /// @dev No flow pays into this contract outside `requestExternalReadSelf`.
    ///      Kept as a recovery surface so accidentally-sent PC remains reachable
    ///      via `rescueNativePC`, which excludes user-owned funds.
    receive() external payable {}
}
