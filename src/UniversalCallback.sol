// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from
    "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {ReadSpec, PendingRead, MIN_CONFIRMATIONS_FLOOR, MAX_CALLBACK_GAS_LIMIT} from "./libraries/ReadTypes.sol";
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
    address public immutable UNIVERSAL_EXECUTOR_MODULE =
        0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    IUniversalCore internal _universalCore;
    address internal _vaultPC;

    bytes32 public constant UVCALLBACK_ADMIN_ROLE =
        keccak256("UVCALLBACK_ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE =
        keccak256("PAUSER_ROLE");

    mapping(uint256 => bool) public fulfilledRequests;
    mapping(uint256 => PendingRead) private _pending;
    uint256 private _requestNonce;
    mapping(string => mapping(string => bool)) public blockedDomains;

    /// @notice Pull-payment ledger. Settlement credits refunds here rather than
    ///         pushing them, so an unreceptive recipient can never brick a
    ///         fulfillment or an expiry.
    /// @dev    Append-only storage: new variables MUST go after this block.
    mapping(address => uint256) public withdrawable;

    /// @notice Sum of every unclaimed balance in `withdrawable`. Held funds are
    ///         user-owned and are excluded from what `sweepFees` may take.
    uint256 public totalWithdrawable;

    /// @notice Total deposits held for requests that have not settled yet. Escrowed
    ///         funds are user-owned and are excluded from what `sweepFees` may take.
    uint256 public totalEscrowed;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address universalCore_,
        address vaultPC_,
        address defaultAdmin
    ) external initializer {
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

    modifier onlyUEModule() {
        if (msg.sender != UNIVERSAL_EXECUTOR_MODULE) {
            revert UniversalCallbackErrors.CallerIsNotUEModule();
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

    function requestExternalReadSelf(
        ReadSpec calldata spec,
        bytes4 callbackSelector,
        uint64 callbackGasLimit
    ) external payable override whenNotPaused nonReentrant returns (uint256 requestId) {
        if (
            bytes(spec.account.chainNamespace).length == 0
            || bytes(spec.account.chainId).length == 0
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
        if (callbackGasLimit == 0 || callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) {
            revert UniversalCallbackErrors.CallbackGasLimitExceeded(callbackGasLimit, MAX_CALLBACK_GAS_LIMIT);
        }

        (uint256 fee, uint256 protocolFee) = _estimateFee(
            spec.account.chainNamespace, spec.account.chainId, callbackGasLimit
        );
        if (msg.value < fee) {
            revert UniversalCallbackErrors.InsufficientFee(msg.value, fee);
        }
        if (msg.value > spec.maxFee) {
            revert UniversalCallbackErrors.ExcessiveFee(msg.value, spec.maxFee);
        }

        requestId = uint256(keccak256(abi.encode(
            block.chainid, block.number, address(this),
            keccak256(abi.encode(spec)), _requestNonce++
        )));

        _pending[requestId] = PendingRead({
            callbackTarget: msg.sender,
            callbackSelector: callbackSelector,
            callbackGasLimit: callbackGasLimit,
            originalFunder: msg.sender,
            feesDeposited: msg.value,
            protocolFee: protocolFee,
            expiryHeight: spec.expiryPushChainHeight
        });
        totalEscrowed += msg.value;

        emit ReadRequested(requestId, spec, msg.sender, msg.sender, msg.value);
    }

    function fulfillExternalCallback(
        uint256 requestId,
        bytes calldata resultData,
        uint64 observedBlockHeight,
        bytes32 observedBlockHash
    ) external override onlyUEModule nonReentrant {
        if (fulfilledRequests[requestId]) {
            revert UniversalCallbackErrors.RequestAlreadyFulfilled(requestId);
        }

        PendingRead memory p = _pending[requestId];
        if (p.callbackTarget == address(0)) {
            revert UniversalCallbackErrors.InvalidCallbackTarget();
        }

        // Effects and settlement complete before any untrusted code runs. The
        // financial outcome is identical whether the callback succeeds or reverts:
        // the protocol fee is earned either way, so only the event differs.
        fulfilledRequests[requestId] = true;
        delete _pending[requestId];
        _settle(requestId, p);

        (bool success, bytes memory reason) =
            p.callbackTarget.call{gas: p.callbackGasLimit}(
                abi.encodeWithSelector(p.callbackSelector, requestId, resultData)
            );

        if (success) {
            emit ReadFulfilled(requestId, resultData, observedBlockHeight, observedBlockHash);
        } else {
            emit CallbackFailed(requestId, reason);
        }
    }

    function expireExternalRead(uint256 requestId) external override onlyUEModule nonReentrant {
        if (fulfilledRequests[requestId]) {
            revert UniversalCallbackErrors.RequestAlreadyFulfilled(requestId);
        }

        PendingRead memory p = _pending[requestId];
        if (p.callbackTarget == address(0)) {
            revert UniversalCallbackErrors.InvalidCallbackTarget();
        }
        if (block.number < p.expiryHeight) {
            revert UniversalCallbackErrors.RequestNotYetExpired();
        }

        fulfilledRequests[requestId] = true;
        delete _pending[requestId];
        _settle(requestId, p);

        emit RequestExpired(requestId, p.originalFunder);
    }

    /// @notice             Claim refunds credited to the caller.
    /// @dev                Deliberately not `whenNotPaused`: pausing halts new
    ///                     requests, it must never trap funds already owed.
    /// @return amount      Amount transferred to the caller.
    function withdraw() external override nonReentrant returns (uint256 amount) {
        amount = withdrawable[msg.sender];
        if (amount == 0) revert UniversalCallbackErrors.NothingToWithdraw();

        withdrawable[msg.sender] = 0;
        totalWithdrawable -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();

        emit RefundWithdrawn(msg.sender, amount);
    }

    /// @dev                Splits a consumed request's deposit: protocol fee to the
    ///                     vault, remainder credited to the funder's pull ledger.
    ///                     Callers MUST have already set `fulfilledRequests` and
    ///                     deleted `_pending` for this request.
    /// @param requestId    Request being settled
    /// @param p            Snapshot of the consumed pending read
    function _settle(uint256 requestId, PendingRead memory p) private {
        // Release escrow before any value leaves, so that
        // `balance >= totalWithdrawable + totalEscrowed` holds across the vault
        // push. `sweepFees` is not `nonReentrant`, so this ordering matters.
        totalEscrowed -= p.feesDeposited;

        uint256 protocolFee = p.protocolFee;
        if (protocolFee > 0) {
            _payProtocolFee(requestId, protocolFee);
        }

        // `feesDeposited >= protocolFee` holds by construction: `_estimateFee`
        // returns `fee = protocolFee + callbackGasCost` and requests below `fee`
        // are rejected at entry.
        uint256 refund = p.feesDeposited - protocolFee;
        if (refund > 0) {
            withdrawable[p.originalFunder] += refund;
            totalWithdrawable += refund;
            emit FeeRefundCredited(requestId, p.originalFunder, refund);
        }
    }

    /// @dev                Pushes the protocol fee to the vault. Reverts loudly on
    ///                     failure rather than masking it: VaultPC accepts plain
    ///                     transfers unconditionally, so a failure here means the
    ///                     contract is short and settlement accounting is wrong.
    ///                     Any future vault MUST keep accepting plain transfers.
    /// @param requestId    Request the fee belongs to
    /// @param amount       Protocol fee amount
    function _payProtocolFee(uint256 requestId, uint256 amount) private {
        address vault = _vaultPC;
        (bool ok, ) = vault.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();
        emit ProtocolFeeDistributed(requestId, vault, amount);
    }

    function sweepFees(address payable recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
        // Escrowed deposits and credited refunds are both user-owned and must
        // never be sweepable. Only unattributed balance may be taken.
        uint256 available = address(this).balance - totalWithdrawable - totalEscrowed;
        if (amount > available) {
            revert UniversalCallbackErrors.InsufficientContractBalance(amount, available);
        }
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert CommonErrors.TransferFailed();
        emit FeeRefunded(0, recipient, amount);
    }

    function _estimateFee(
        string calldata chainNamespace,
        string calldata chainId,
        uint64 callbackGasLimit
    ) internal view returns (uint256 fee, uint256 baseFee) {
        baseFee = _universalCore.readBaseFeeByChainNamespace(chainNamespace, chainId);
        uint256 callbackGasCost = uint256(callbackGasLimit) * tx.gasprice;
        fee = baseFee + callbackGasCost;
    }

    function estimateFee(
        string calldata chainNamespace,
        string calldata chainId,
        uint64 callbackGasLimit
    ) external view override returns (uint256) {
        (uint256 fee,) = _estimateFee(chainNamespace, chainId, callbackGasLimit);
        return fee;
    }

    function isFulfilled(uint256 requestId) external view override returns (bool) {
        return fulfilledRequests[requestId];
    }

    function getPendingRead(uint256 requestId) external view returns (PendingRead memory) {
        return _pending[requestId];
    }

    function updateBlockedDomain(
        string calldata chainNamespace,
        string calldata chainId,
        bool blocked
    ) external onlyUvCallbackAdmin {
        blockedDomains[chainNamespace][chainId] = blocked;
        emit DomainUpdated(chainNamespace, chainId, blocked);
    }

    function isDomainBlocked(
        string calldata chainNamespace,
        string calldata chainId
    ) external view returns (bool) {
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
    ///      via `sweepFees`, which excludes credited refunds.
    receive() external payable {}
}
