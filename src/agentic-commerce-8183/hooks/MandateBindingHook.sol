// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseERC8183Hook} from "./BaseERC8183Hook.sol";
import {IAgenticCommerce} from "../interfaces/IAgenticCommerce.sol";
import {IAGWFactory} from "../interfaces/external/IAGWFactory.sol";
import {ISmartSession} from "../interfaces/external/ISmartSession.sol";

/// @title MandateBindingHook
/// @notice Binds each job to the funding AGW's mandate and allows one live job per AGW.
/// @dev - Acts only in `beforeAction(fund)` (H-09); every other action passes through.
///      - Scope (D-25): the rule covers jobs that name this hook; hookless jobs are invisible to it.
///      - An AGW is freed by reading kernel job status (H-05), so unhooked `claimRefund` frees it too.
///      - Deployed behind `TransparentUpgradeableProxy` (D-15); storage continues the base at slot 50.
contract MandateBindingHook is BaseERC8183Hook {
    /// @notice The job ↔ mandate record.
    struct Binding {
        address agw;
        bytes32 permissionId;
    }

    /// @notice `fund.optParams` is not exactly 32 bytes.
    error InvalidOptParams(uint256 length);
    /// @notice The funding client is not a factory-deployed AGW.
    error NotAnAGW(address caller);
    /// @notice The mandate is not enabled on this AGW.
    error MandateNotLive(address agw, bytes32 permissionId);
    /// @notice The AGW already has a Funded or Submitted job under this hook.
    error AGWHasLiveJob(address agw, uint256 liveJobId);

    /// @notice A job was bound to an AGW's mandate at `fund`.
    event MandateBound(uint256 indexed jobId, address indexed agw, bytes32 indexed permissionId);

    // ───────── storage — slots 50..103 (base owns 0..49) ─────────

    /// @notice AGW factory, used to prove the client is an AGW.
    address public agwFactory;
    /// @notice SmartSession engine, used to prove the mandate is live.
    address public sessionEngine;
    /// @notice Job id → bound mandate.
    /// @dev - `permissionId` is not globally unique across wallets; always read with `agw`.
    mapping(uint256 => Binding) public mandateOf;
    /// @notice AGW → last job bound; live only while that job is Funded or Submitted.
    mapping(address => uint256) public liveJobOf;
    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the proxy.
    /// @param kernel_ The kernel proxy.
    /// @param agwFactory_ The AGW factory proxy.
    /// @param sessionEngine_ The SmartSession engine.
    function initialize(address kernel_, address agwFactory_, address sessionEngine_) external initializer {
        if (kernel_ == address(0) || agwFactory_ == address(0) || sessionEngine_ == address(0)) revert ZeroAddress();
        __BaseERC8183Hook_init(kernel_);
        agwFactory = agwFactory_;
        sessionEngine = sessionEngine_;
    }

    /// @notice Whether an AGW currently holds a live job under this hook.
    /// @dev - Live = the recorded job is Funded or Submitted in the kernel.
    /// @param agw The wallet.
    /// @return True if the AGW cannot fund another job here.
    function isAGWBusy(address agw) public view returns (bool) {
        uint256 id = liveJobOf[agw];
        if (id == 0) return false;
        IAgenticCommerce.JobStatus s = IAgenticCommerce(kernel).getJob(id).status;
        return s == IAgenticCommerce.JobStatus.Funded || s == IAgenticCommerce.JobStatus.Submitted;
    }

    /// @dev Checks, in order: optParams length · client is an AGW · mandate live · AGW not busy.
    ///      - `caller` is the job's client — the kernel checks it before calling the hook.
    ///      - Runs in `beforeAction`, so any revert leaves the job Open with no escrow moved.
    function _preFund(uint256 jobId, address caller, bytes memory optParams) internal override {
        if (optParams.length != 32) revert InvalidOptParams(optParams.length);
        bytes32 permissionId = abi.decode(optParams, (bytes32));
        if (!IAGWFactory(agwFactory).isWallet(caller)) revert NotAnAGW(caller);
        if (!ISmartSession(sessionEngine).isPermissionEnabled(permissionId, caller)) {
            revert MandateNotLive(caller, permissionId);
        }
        if (isAGWBusy(caller)) revert AGWHasLiveJob(caller, liveJobOf[caller]); // 2nd read only on revert

        mandateOf[jobId] = Binding({agw: caller, permissionId: permissionId});
        liveJobOf[caller] = jobId;
        emit MandateBound(jobId, caller, permissionId);
    }
}
