// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {E2E} from "./E2EConfig.sol";
import {E2EPaymentToken} from "./E2EMocks.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalHook} from "../../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {UniversalEvaluator} from "../../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IUniversalCallback} from "../../../src/interfaces/IUniversalCallback.sol";
import {RequestStatus} from "../../../src/libraries/ReadTypes.sol";
import {IUniversalCoreHeights} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {UniversalPayload, VerificationType, Multicall, MULTICALL_SELECTOR} from "../../../src/libraries/Types.sol";

/// @notice Push's outbound request (push-chain-gateway-contracts `TypesUGPC.sol`).
struct UniversalOutboundTxRequest {
    bytes recipient; // the destination account (20 bytes); for a payload, the CEA that runs it
    address token; // the PRC20 that names the destination chain and its gas token
    uint256 amount; // 0: payload only
    uint256 gasLimit; // destination gas
    uint256 gasPrice; // 0: the chain's default
    uint256 maxPCForGas; // 0: no cap
    bytes payload;
    address revertRecipient;
}

interface IE2EGatewayPC {
    function sendUniversalTxOutbound(UniversalOutboundTxRequest calldata req) external payable;
}

interface IE2ECoreFees {
    function getOutboundTxGasAndFees(address prc20, uint256 gasLimit)
        external
        view
        returns (
            address gasToken,
            uint256 gasFee,
            uint256 protocolFee,
            uint256 gasPrice,
            string memory ns,
            uint256 used
        );
}

/// @notice The UEA functions a relayer needs: anyone may send a payload its owner signed.
interface IE2EUEA {
    function nonce() external view returns (uint256);
    function getUniversalPayloadHash(UniversalPayload memory payload) external view returns (bytes32);
    function executeUniversalTx(UniversalPayload calldata payload, bytes calldata signature) external;
}

/// @title E2EJob — one allocation job on Push Donut (see README.md)
/// @notice open()          client creates the job, provider prices it, client prefunds and funds: the hook binds it
///                         and the evaluator freezes the spec and sends the two PRE reads. In UEA mode the client's
///                         calls are UEA payloads the client key signs and the relayer sends.
///         outbound()      UEA mode: the UEA sends an outbound transaction; on Base Sepolia the Vault has the CEA
///                         run approve + supply / approve + deposit itself (the client's own USDC, in its CEA).
///         submit()        provider submits: the evaluator fixes the end blocks and sends the two POST reads.
///         status()        the job, its evaluation and every read.
///         retrySnapshot() provider: re-send unreadable PRE reads (before the evaluation starts).
///         sendReads()     provider: send or re-send the evaluation's reads.
///         settle()        anyone: apply a verdict the kernel refused inside the callback.
///         refund()        anyone: `claimRefund` once expired (+1 h if Submitted), then `claimPrepaid`.
/// @dev Keys: CLIENT_PRIVATE_KEY, PROVIDER_PRIVATE_KEY, RELAYER_PRIVATE_KEY (default: the client key). The accounts
///      come from `E2EAccounts`; the job id from JOB_ID or the state file.
contract E2EJob is Script {
    string[4] internal LABELS =
        ["aUSDC after  (POST)", "Morpho after (POST)", "aUSDC before (PRE) ", "Morpho before(PRE) "];

    /// @dev BUDGET (payment token, 6 decimals; default 100) · JOB_EXPIRY (s; default 7200) ·
    ///      MIN_CONFIRMATIONS (Base Sepolia blocks per read; default 3) · ALLOC_TOTAL (default 1000 USDC).
    function open() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        E2E.Accounts memory acc = E2E.loadAccounts();
        require(acc.measured != address(0), "open: run `accounts` (its Base Sepolia half resolves the CEA) first");
        _requireClientFree(p, acc.client);
        require(
            IUniversalCoreHeights(E2E.UNIVERSAL_CORE).chainHeightByChainNamespace(E2E.BASE_KEY)
                >= vm.envOr("MIN_FUND_HEIGHT", uint256(0)),
            "open: Push's Base Sepolia height is below the dummies' deploy block (PRE reads would find no code); wait"
        );
        uint16 minConfirmations = uint16(vm.envOr("MIN_CONFIRMATIONS", uint256(3)));
        string memory description =
            string(abi.encode(E2E.allocationSpec(E2E.loadBase(), acc.measured, E2E.total(), minConfirmations)));
        uint256 budget = vm.envOr("BUDGET", uint256(100e6));

        uint256 jobId = _createAndPrice(p, acc, description, budget);
        uint256 prepay = _prefundAndFund(p, acc, jobId, keccak256(bytes(description)), budget);
        E2E.saveJob(jobId, keccak256(bytes(description)), acc.client, acc.measured);

        console.log("=== Job opened and funded ===");
        console.log("job id:   ", jobId);
        console.log(acc.uea ? "client (UEA):" : "client:   ", acc.client);
        console.log(acc.uea ? "measured (CEA, Base Sepolia):" : "measured: ", acc.measured);
        console.log("provider: ", E2E.provider());
        console.log("budget:   ", budget);
        console.log("prepaid PC (wei):", prepay);
        console.log("asks for: (aUSDC + Morpho) to grow by >=", E2E.total() * 9999 / 10_000, "and both venues to grow");
    }

    /// @dev The hook allows one active job per client.
    function _requireClientFree(E2E.PushAddrs memory p, address client) internal view {
        uint256 active = UniversalHook(p.hook).activeJobOf(client);
        if (active == 0) return;
        revert(
            string.concat(
                "client has an active job (",
                vm.toString(active),
                "): finish it, or run `refund` once it has expired"
            )
        );
    }

    /// @dev The client creates the job; the provider prices it, leaving the criteria the description's.
    function _createAndPrice(E2E.PushAddrs memory p, E2E.Accounts memory acc, string memory description, uint256 budget)
        internal
        returns (uint256 jobId)
    {
        uint256 expiredAt = block.timestamp + vm.envOr("JOB_EXPIRY", uint256(2 hours));
        if (acc.uea) {
            Multicall[] memory calls = new Multicall[](1);
            calls[0] = Multicall({
                to: p.kernel,
                value: 0,
                data: abi.encodeCall(
                    IAgenticCommerce.createJob, (E2E.provider(), p.evaluator, expiredAt, description, p.hook)
                )
            });
            _asUea(acc.client, calls);
            jobId = IAgenticCommerce(p.kernel).jobCounter(); // our kernel: nobody else creates jobs
        } else {
            vm.startBroadcast(E2E.clientKey());
            jobId = IAgenticCommerce(p.kernel).createJob(E2E.provider(), p.evaluator, expiredAt, description, p.hook);
            vm.stopBroadcast();
        }

        vm.startBroadcast(E2E.providerKey());
        IAgenticCommerce(p.kernel).setBudget(jobId, budget, "");
        vm.stopBroadcast();
    }

    /// @dev Prepays the reads with one spare round for retries (the rest goes back to the client), then funds: the
    ///      hook binds the job and the evaluator freezes the spec and sends the PRE reads. Anyone may mint the dummy
    ///      token and prepay, so in UEA mode the relayer does both and the UEA only approves and funds.
    function _prefundAndFund(
        E2E.PushAddrs memory p,
        E2E.Accounts memory acc,
        uint256 jobId,
        bytes32 specHash,
        uint256 budget
    ) internal returns (uint256 prepay) {
        (uint256 snapshotCost, uint256 evaluationCost) = UniversalEvaluator(p.evaluator).prefundCost(jobId);
        prepay = 2 * (snapshotCost + evaluationCost);
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = Multicall({to: p.paymentToken, value: 0, data: abi.encodeCall(IERC20.approve, (p.kernel, budget))});
        calls[1] = Multicall({
            to: p.kernel,
            value: 0,
            data: abi.encodeCall(IAgenticCommerce.fund, (jobId, budget, abi.encode(E2E.RULES_ID, specHash, bytes(""))))
        });

        vm.startBroadcast(acc.uea ? E2E.relayerKey() : E2E.clientKey());
        E2EPaymentToken(p.paymentToken).mint(acc.client, budget);
        UniversalEvaluator(p.evaluator).prefund{value: prepay}(jobId);
        if (!acc.uea) {
            IERC20(p.paymentToken).approve(p.kernel, budget);
            IAgenticCommerce(p.kernel).fund(jobId, budget, abi.encode(E2E.RULES_ID, specHash, bytes("")));
        }
        vm.stopBroadcast();
        if (acc.uea) _asUea(acc.client, calls);
    }

    /// @dev Runs `calls` as the UEA: the client key signs the payload, the relayer sends it.
    function _asUea(address uea, Multicall[] memory calls) internal {
        UniversalPayload memory payload;
        payload.to = uea; // unused for a multicall
        payload.data = abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));
        payload.nonce = IE2EUEA(uea).nonce();
        payload.vType = VerificationType.signedVerification;
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(E2E.clientKey(), IE2EUEA(uea).getUniversalPayloadHash(payload));
        vm.startBroadcast(E2E.relayerKey());
        IE2EUEA(uea).executeUniversalTx(payload, abi.encodePacked(r, sig, v));
        vm.stopBroadcast();
    }

    /// @dev ALLOC_AAVE / ALLOC_MORPHO split the work (defaults 600 / 400). OUTBOUND_GAS_LIMIT is the Base Sepolia gas
    ///      (default 1,000,000; deploying the CEA and the four calls measured ~0.41M). OUTBOUND_PC is sent for the fee
    ///      (default 1 PC); the gateway swaps what the gas costs and refunds the rest to the UEA.
    function outbound() external {
        _requirePush();
        E2E.Accounts memory acc = E2E.loadAccounts();
        require(acc.uea, "outbound: UEA mode only (CLIENT_MODE=uea)");
        require(acc.measured != address(0), "outbound: run `accounts` first");
        uint256 gasLimit = vm.envOr("OUTBOUND_GAS_LIMIT", uint256(1_000_000));
        uint256 value = vm.envOr("OUTBOUND_PC", uint256(1 ether));
        (, uint256 gasFee, uint256 protocolFee,,,) =
            IE2ECoreFees(E2E.UNIVERSAL_CORE).getOutboundTxGasAndFees(E2E.PETH_BASE, gasLimit);

        UniversalOutboundTxRequest memory req;
        req.recipient = abi.encodePacked(acc.measured);
        req.token = E2E.PETH_BASE;
        req.gasLimit = gasLimit;
        req.payload = E2E.ceaAllocationPayload(
            E2E.loadBase(),
            acc.measured,
            vm.envOr("ALLOC_AAVE", uint256(600e6)),
            vm.envOr("ALLOC_MORPHO", uint256(400e6))
        );
        req.revertRecipient = acc.client;

        if (acc.client.balance < value) {
            vm.startBroadcast(E2E.relayerKey()); // the UEA pays the fee from its own PC
            (bool ok,) = acc.client.call{value: value - acc.client.balance}("");
            require(ok, "outbound: topping up the UEA failed");
            vm.stopBroadcast();
        }
        Multicall[] memory calls = new Multicall[](1);
        calls[0] = Multicall({
            to: E2E.GATEWAY_PC, value: value, data: abi.encodeCall(IE2EGatewayPC.sendUniversalTxOutbound, (req))
        });
        _asUea(acc.client, calls);

        console.log("=== Outbound sent by the UEA", acc.client, "===");
        console.log("to the CEA on Base Sepolia:", acc.measured);
        console.log("gas limit:", gasLimit);
        console.log("gas fee (pETH wei):", gasFee, "protocol fee (PC wei):", protocolFee);
        console.log("PC sent (excess refunded):", value);
    }

    /// @dev MIN_END_HEIGHT: the Base Sepolia block the allocation landed in. Submitting before the tracked height
    ///      reaches it would measure the state before the work.
    function submit() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        uint256 jobId = E2E.jobId();
        UniversalEvaluator ue = UniversalEvaluator(p.evaluator);
        require(_status(p, jobId) == IAgenticCommerce.JobStatus.Funded, "submit: the job is not Funded");
        require(ue.ready(jobId), "submit: the PRE reads are not answered yet (wait, or retry-snapshot)");

        uint256 tracked = IUniversalCoreHeights(E2E.UNIVERSAL_CORE).chainHeightByChainNamespace(E2E.BASE_KEY);
        uint256 minEnd = vm.envOr("MIN_END_HEIGHT", uint256(0));
        require(tracked >= minEnd, "submit: Push's Base Sepolia height has not reached the allocation block yet");
        require(tracked > ue.fundHeightOf(jobId, 0), "submit: Push's Base Sepolia height has not moved since fund");

        vm.startBroadcast(E2E.providerKey());
        IAgenticCommerce(p.kernel).submit(jobId, keccak256("e2e: allocated"), "");
        vm.stopBroadcast();

        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        console.log("=== Submitted job", jobId, "===");
        console.log("end blocks fixed at about Base Sepolia height", tracked);
        if (!e.started) console.log("WARNING: the POST reads did not go out inside submit: run `send-reads`");
    }

    function status() external view {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        uint256 jobId = E2E.jobId();
        UniversalEvaluator ue = UniversalEvaluator(p.evaluator);
        IAgenticCommerce.Job memory job = IAgenticCommerce(p.kernel).getJob(jobId);
        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        IUniversalCoreHeights core = IUniversalCoreHeights(E2E.UNIVERSAL_CORE);

        console.log("=== Job", jobId, "===");
        console.log("status:       ", _statusName(job.status));
        console.log("client:       ", job.client);
        console.log("measured on Base Sepolia:", E2E.jobMeasured());
        console.log("expires at:   ", uint256(job.expiredAt), "now:", block.timestamp);
        console.log("budget:       ", job.budget);
        console.log("client eUSD balance:  ", IERC20(p.paymentToken).balanceOf(job.client));
        console.log("provider eUSD balance:", IERC20(p.paymentToken).balanceOf(job.provider));
        console.log("prepaid PC left (wei):", ue.prepaidOf(jobId));
        console.log("Base Sepolia tracked height:", core.chainHeightByChainNamespace(E2E.BASE_KEY));
        uint256 observedAt = core.timestampObservedAtByChainNamespace(E2E.BASE_KEY);
        console.log("  observed (s ago):", block.timestamp > observedAt ? block.timestamp - observedAt : 0); // can lead the simulated block
        console.log("--- evaluation ---");
        console.log("snapshot ready:", ue.ready(jobId));
        console.log("end blocks fixed:", e.endFixed, "| POST reads sent:", e.started);
        console.log("reads pending:", e.pending, "| done:", e.done);
        console.log("verdict:", _verdictName(uint8(e.verdict)), "| applied on the kernel:", e.applied);
        for (uint256 c; c < 3; ++c) {
            console.log(string.concat("check ", vm.toString(c), ": ", _checkName((e.checkRes >> (2 * c)) & 3)));
        }
        console.log("--- reads ---");
        for (uint256 i; i < 4; ++i) {
            bool pre = i >= 2;
            (bool ok, int256 value) = ue.answerOf(jobId, i);
            uint256 req = ue.requestOf(jobId, i);
            console.log(
                string.concat(
                    "read ",
                    vm.toString(i),
                    " ",
                    LABELS[i],
                    " block ",
                    vm.toString(pre ? ue.fundHeightOf(jobId, i) : ue.endHeightOf(jobId, i)),
                    " | request ",
                    req == 0 ? "-" : _requestName(IUniversalCallback(E2E.READ_STATE).statusOf(req)),
                    " | answer ",
                    ok ? vm.toString(value) : "none"
                )
            );
        }
    }

    /// @dev VALUE: PC (wei) to add; the prepaid spare round usually covers it.
    function retrySnapshot() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        vm.startBroadcast(E2E.providerKey()); // the client or the provider may; the provider is an EOA in both modes
        UniversalEvaluator(p.evaluator).retrySnapshot{value: vm.envOr("VALUE", uint256(0))}(E2E.jobId());
        vm.stopBroadcast();
    }

    /// @dev VALUE: PC (wei) to add; the prepaid spare round usually covers it.
    function sendReads() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        vm.startBroadcast(E2E.providerKey());
        UniversalEvaluator(p.evaluator).sendReads{value: vm.envOr("VALUE", uint256(0))}(E2E.jobId());
        vm.stopBroadcast();
    }

    function settle() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        vm.startBroadcast(E2E.relayerKey());
        UniversalEvaluator(p.evaluator).settle(E2E.jobId());
        vm.stopBroadcast();
    }

    function refund() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        uint256 jobId = E2E.jobId();
        IAgenticCommerce.JobStatus s = _status(p, jobId);
        vm.startBroadcast(E2E.relayerKey()); // both are open to anyone and pay the job's client
        if (
            s == IAgenticCommerce.JobStatus.Open || s == IAgenticCommerce.JobStatus.Funded
                || s == IAgenticCommerce.JobStatus.Submitted
        ) IAgenticCommerce(p.kernel).claimRefund(jobId); // reverts until expired (+1 h if Submitted)
        UniversalEvaluator(p.evaluator).claimPrepaid(jobId);
        vm.stopBroadcast();
    }

    function _status(E2E.PushAddrs memory p, uint256 jobId) internal view returns (IAgenticCommerce.JobStatus) {
        return IAgenticCommerce(p.kernel).getJob(jobId).status;
    }

    function _requirePush() internal view {
        require(block.chainid == E2E.PUSH_DONUT_CHAIN_ID, "E2EJob: not Push Donut (42101)");
    }

    function _statusName(IAgenticCommerce.JobStatus s) internal pure returns (string memory) {
        string[6] memory n = ["Open", "Funded", "Submitted", "Completed", "Rejected", "Expired"];
        return n[uint8(s)];
    }

    function _verdictName(uint8 v) internal pure returns (string memory) {
        string[4] memory n = ["NONE", "PASS", "FAIL", "INCONCLUSIVE"];
        return n[v];
    }

    function _checkName(uint256 r) internal pure returns (string memory) {
        return r == 1 ? "PASS" : r == 2 ? "FAIL" : "UNKNOWN";
    }

    function _requestName(RequestStatus s) internal pure returns (string memory) {
        string[5] memory n = ["NONE", "PENDING", "EXECUTED", "SETTLED", "EXPIRED"];
        return n[uint8(s)];
    }
}
