// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {console} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {E2E} from "../e2e/E2EConfig.sol";
import {E2EJob, UniversalOutboundTxRequest, IE2EGatewayPC} from "../e2e/E2EJob.s.sol";
import {Demo} from "./DemoConfig.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalEvaluator} from "../../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IUniversalCoreHeights} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {JobSpec} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {Multicall} from "../../../src/libraries/Types.sol";

/// @title DemoJob — the three demo jobs on Push Donut (see README.md)
/// @notice open(job)       the client UEA creates job 1, 2 or 3; the provider prices it; the UEA funds it. The
///                         evaluator freezes the criteria and sends the PRE reads.
///         bridgeOut(chain) the client UEA sends its ETH to its own CEA on Base Sepolia (0) or Ethereum Sepolia (1)
///                         with the CEA's work: wrap, then supply to Aave and/or deposit to the vault.
///         submit()        the provider submits; the evaluator fixes the end blocks and sends the POST reads.
///         report()        the job, its verdict and every read.
///         claim()         `claimPrepaid` once the job is over.
/// @dev State: E2E_STATE_DIR (push.json, accounts.json from the e2e scripts) plus demo-job.json written here.
///      Env: JOB (1..3), CEA_BASE, CEA_SEP, VAULT, PRINCIPAL (wei; default 0.01 ETH), TO_AAVE, TO_VAULT.
contract DemoJob is E2EJob {
    function openJob() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        E2E.Accounts memory acc = E2E.loadAccounts();
        require(acc.uea, "demo: UEA client only");
        _requireClientFree(p, acc.client);

        uint256 job = vm.envUint("JOB");
        uint256 principal = vm.envOr("PRINCIPAL", uint256(0.01 ether));
        uint16 conf = uint16(vm.envOr("MIN_CONFIRMATIONS", uint256(3)));
        JobSpec memory s;
        if (job == 1) s = Demo.job1(vm.envAddress("CEA_BASE"), principal, conf);
        else if (job == 2) s = Demo.job2(vm.envAddress("CEA_BASE"), vm.envAddress("VAULT"), principal, conf);
        else if (job == 3) s = Demo.job3(vm.envAddress("CEA_BASE"), vm.envAddress("CEA_SEP"), principal, conf);
        else revert("JOB must be 1, 2 or 3");
        s.origin = keccak256(abi.encodePacked("demo-job-", vm.toString(job)));

        string memory description = string(abi.encode(s));
        uint256 budget = vm.envOr("BUDGET", uint256(5e6));
        uint256 jobId = _createAndPrice(p, acc, description, budget);
        uint256 prepay = _prefundAndFund(p, acc, jobId, keccak256(bytes(description)), budget);

        if (vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) {
            string memory k = "demo";
            vm.serializeUint(k, "job", job);
            vm.serializeUint(k, "jobId", jobId);
            vm.serializeUint(k, "principal", principal);
            string memory out = vm.serializeBytes32(k, "specHash", keccak256(bytes(description)));
            vm.writeJson(out, string.concat(E2E.dir(), "/demo-job.json"));
        }
        console.log("=== Demo job", job, "opened and funded ===");
        console.log("job id:", jobId);
        console.log("principal (wei):", principal);
        console.log("prepaid PC (wei):", prepay);
    }

    /// @dev CHAIN 0 = Base Sepolia, 1 = Ethereum Sepolia. The UEA approves the gateway for the pETH it bridges and
    ///      pays the fee in PC (OUTBOUND_PC, excess refunded).
    function bridgeOut() external {
        _requirePush();
        E2E.Accounts memory acc = E2E.loadAccounts();
        bool sep = vm.envUint("CHAIN") == 1;
        address cea = vm.envAddress(sep ? "CEA_SEP" : "CEA_BASE");
        uint256 toAave = vm.envOr("TO_AAVE", uint256(0));
        uint256 toVault = vm.envOr("TO_VAULT", uint256(0));
        uint256 amount = toAave + toVault;
        require(amount > 0, "outbound: nothing to send");
        address peth = sep ? Demo.PETH_SEP : Demo.PETH_BASE;
        require(IERC20(peth).balanceOf(acc.client) >= amount, "outbound: the UEA holds too little pETH; bridge first");

        UniversalOutboundTxRequest memory req;
        req.recipient = abi.encodePacked(cea);
        req.token = peth;
        req.amount = amount;
        req.gasLimit = vm.envOr("OUTBOUND_GAS_LIMIT", uint256(1_000_000));
        req.payload = sep
            ? Demo.supplyPayload(Demo.SEP_WETH, Demo.SEP_POOL, address(0), cea, toAave, 0)
            : Demo.supplyPayload(Demo.BASE_WETH, Demo.BASE_POOL, vm.envOr("VAULT", address(0)), cea, toAave, toVault);
        req.revertRecipient = acc.client;

        uint256 pc = vm.envOr("OUTBOUND_PC", uint256(1 ether));
        if (acc.client.balance < pc) {
            vm.startBroadcast(E2E.relayerKey());
            (bool ok,) = acc.client.call{value: pc - acc.client.balance}("");
            require(ok, "outbound: topping up the UEA failed");
            vm.stopBroadcast();
        }
        Multicall[] memory calls = new Multicall[](2);
        calls[0] = Multicall({to: peth, value: 0, data: abi.encodeCall(IERC20.approve, (Demo.GATEWAY_PC, amount))});
        calls[1] = Multicall({
            to: Demo.GATEWAY_PC, value: pc, data: abi.encodeCall(IE2EGatewayPC.sendUniversalTxOutbound, (req))
        });
        _asUea(acc.client, calls);
        console.log("=== Outbound sent by the UEA", acc.client, sep ? "to Ethereum Sepolia" : "to Base Sepolia");
        console.log("CEA:", cea);
        console.log("ETH (wei) to Aave / vault:", toAave, toVault);
    }

    /// @dev MIN_BASE / MIN_SEP: the blocks the work landed in; the tracked heights must have reached them.
    function submitJob() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        uint256 jobId = _demoJobId();
        IUniversalCoreHeights core = IUniversalCoreHeights(E2E.UNIVERSAL_CORE);
        require(core.chainHeightByChainNamespace("eip155:84532") >= vm.envOr("MIN_BASE", uint256(0)), "Base height");
        require(core.chainHeightByChainNamespace("eip155:11155111") >= vm.envOr("MIN_SEP", uint256(0)), "Sep height");
        vm.startBroadcast(E2E.providerKey());
        IAgenticCommerce(p.kernel).submit(jobId, keccak256("demo"), "");
        vm.stopBroadcast();
        console.log("=== Submitted job", jobId, "===");
    }

    function report() external view {
        E2E.PushAddrs memory p = E2E.loadPush();
        uint256 jobId = _demoJobId();
        UniversalEvaluator ue = UniversalEvaluator(p.evaluator);
        UniversalEvaluator.Evaluation memory e = ue.evaluationOf(jobId);
        console.log("job", jobId, "status", uint8(IAgenticCommerce(p.kernel).getJob(jobId).status));
        console.log("verdict (0 none 1 pass 2 fail 3 inconclusive):", uint8(e.verdict));
        console.log("applied:", e.applied, "ready:", ue.ready(jobId));
        uint256 n = abi.decode(bytes(IAgenticCommerce(p.kernel).getJob(jobId).description), (JobSpec)).reads.length;
        for (uint256 i; i < n; ++i) {
            (bool ok, int256 v) = ue.answerOf(jobId, i);
            console.log(i, ok, vm.toString(v));
        }
    }

    function claim() external {
        _requirePush();
        E2E.PushAddrs memory p = E2E.loadPush();
        vm.startBroadcast(E2E.relayerKey());
        UniversalEvaluator(p.evaluator).claimPrepaid(_demoJobId());
        vm.stopBroadcast();
    }

    function _demoJobId() internal view returns (uint256) {
        uint256 id = vm.envOr("JOB_ID", uint256(0));
        if (id != 0) return id;
        return vm.parseJsonUint(vm.readFile(string.concat(E2E.dir(), "/demo-job.json")), ".jobId");
    }
}
