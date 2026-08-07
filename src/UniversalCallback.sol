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
        fulfilledRequests[requestId] = true;

        PendingRead memory p = _pending[requestId];
        if (p.callbackTarget == address(0)) {
            revert UniversalCallbackErrors.InvalidCallbackTarget();
        }
        delete _pending[requestId];

        (bool success, bytes memory reason) =
            p.callbackTarget.call{gas: p.callbackGasLimit}(
                abi.encodeWithSelector(p.callbackSelector, requestId, resultData)
            );

        if (success) {
            emit ReadFulfilled(requestId, resultData, observedBlockHeight, observedBlockHash);

            if (p.protocolFee > 0 && address(this).balance >= p.protocolFee) {
                (bool ok, ) = _vaultPC.call{value: p.protocolFee}("");
                if (!ok) revert CommonErrors.TransferFailed();
                emit ProtocolFeeDistributed(requestId, _vaultPC, p.protocolFee);
            }

            uint256 refund = p.feesDeposited - p.protocolFee;
            if (refund > 0) {
                (bool ok, ) = p.originalFunder.call{value: refund}("");
                if (!ok) revert CommonErrors.TransferFailed();
                emit FeeRefunded(requestId, p.originalFunder, refund);
            }
        } else {
            emit CallbackFailed(requestId, reason);
            if (p.feesDeposited > 0) {
                (bool ok, ) = p.originalFunder.call{value: p.feesDeposited}("");
                if (!ok) revert CommonErrors.TransferFailed();
                emit FeeRefunded(requestId, p.originalFunder, p.feesDeposited);
            }
        }
    }

    function expireExternalRead(uint256 requestId) external override onlyUEModule nonReentrant {
        if (fulfilledRequests[requestId]) {
            revert UniversalCallbackErrors.RequestAlreadyFulfilled(requestId);
        }
        fulfilledRequests[requestId] = true;

        PendingRead memory p = _pending[requestId];
        if (p.callbackTarget == address(0)) {
            revert UniversalCallbackErrors.InvalidCallbackTarget();
        }
        if (block.number < p.expiryHeight) {
            revert UniversalCallbackErrors.RequestNotYetExpired();
        }
        delete _pending[requestId];

        emit RequestExpired(requestId, p.originalFunder);
    }

    function sweepFees(address payable recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
        if (amount > address(this).balance) {
            revert UniversalCallbackErrors.InsufficientContractBalance(amount, address(this).balance);
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

    receive() external payable {}
}
