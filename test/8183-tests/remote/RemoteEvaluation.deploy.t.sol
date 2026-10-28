// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {RemoteBase} from "./RemoteBase.t.sol";
import {RemoteEvaluationDeploy} from "../../../scripts/agentic-commerce-8183/remote/RemoteEvaluationDeploy.sol";
import {DeployRemoteEvaluationScript} from "../../../scripts/agentic-commerce-8183/remote/deployRemoteEvaluation.s.sol";
import {IAgenticCommerce} from "../../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {JobSpec} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {LAYOUT_V} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";

/// @notice Stands in for the deployer on a remote chain: its CREATEs don't move the Push deployer's nonce, as on a
///         real second chain.
contract RemoteSideDeployer {
    function deploy(RemoteEvaluationDeploy.GatewayParams memory p)
        external
        returns (RemoteEvaluationDeploy.GatewayDeployed memory)
    {
        return RemoteEvaluationDeploy.deployGateway(p);
    }
}

/// @notice The deploy route, through the same library the script runs: predict (step 1), gateway (step 2), evaluator
///         (step 3), wiring checks, then a job evaluated end to end through the deployed pair.
contract RemoteEvaluationDeployTest is RemoteBase {
    RemoteSideDeployer internal remoteSide;

    function setUp() public override {
        super.setUp(); // the fixture's own pair, replaced below
        remoteSide = new RemoteSideDeployer();
    }

    function _gatewayParams(address predicted) internal view returns (RemoteEvaluationDeploy.GatewayParams memory p) {
        p.universalGateway = address(ugw);
        p.remoteEvaluator = predicted;
        p.feeRecipient = feeRecipient;
        p.proxyAdminOwner = proxyAdminOwner;
        p.readGas = READ_GAS;
        p.minSettleWindow = SETTLE_WINDOW;
        p.maxConfirmations = 64;
        p.kernels = new address[](1);
        p.kernels[0] = kernel_();
        p.layouts = new uint8[](1);
        p.layouts[0] = LAYOUT_V;
    }

    function _evaluatorParams(address gateway, address expected)
        internal
        view
        returns (RemoteEvaluationDeploy.EvaluatorParams memory p)
    {
        p.ueaFactory = address(ueaFactory);
        p.universalGatewayPC = address(ugpc);
        p.readState = address(readState);
        p.universalCore = address(core);
        p.proxyAdminOwner = proxyAdminOwner;
        p.read = _readConfig();
        p.remotes = new RemoteEvaluator.Remote[](1);
        p.remotes[0] = RemoteEvaluator.Remote({
            chainId: CHAIN,
            gateway: gateway,
            settleGasLimit: SETTLE_GAS,
            senderCodeHash: EvaluationGateway(payable(gateway)).senderCodeHash()
        });
        p.expected = expected;
    }

    function _deployAll() internal returns (EvaluationGateway g, RemoteEvaluator r) {
        address predicted = RemoteEvaluationDeploy.predictEvaluator(address(this)); // step 1
        RemoteEvaluationDeploy.GatewayDeployed memory gd = remoteSide.deploy(_gatewayParams(predicted)); // step 2
        RemoteEvaluationDeploy.EvaluatorDeployed memory ed =
            RemoteEvaluationDeploy.deployEvaluator(_evaluatorParams(address(gd.gateway), predicted), address(this)); // 3
        return (gd.gateway, ed.evaluator);
    }

    function test_deploy_wiresBothSides_thenEvaluates() public {
        (EvaluationGateway g, RemoteEvaluator r) = _deployAll();
        assertEq(g.REMOTE_EVALUATOR(), address(r));
        assertEq(r.gatewayOf(CHAIN), address(g));

        // the network sees the new pair
        gw = g;
        re = r;
        ceaFactory.set(evaluatorCEA, address(r));

        (uint256 jobId, bytes32 key) = _verified(_exampleSpec(), 600e6, 400e6);
        _track(block.number);
        _inboundOk();
        _answerPost(key);
        _sendVerdict(key);
        assertTrue(_outbound());
        assertEq(uint8(kernel.getJob(jobId).status), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    function test_deploy_nonceMoved_reverts() public {
        address predicted = RemoteEvaluationDeploy.predictEvaluator(address(this));
        RemoteEvaluationDeploy.GatewayDeployed memory gd = remoteSide.deploy(_gatewayParams(predicted));
        RemoteEvaluationDeploy.EvaluatorParams memory p = _evaluatorParams(address(gd.gateway), predicted);
        new RemoteSideDeployer(); // the Push deployer sent something else in between
        vm.expectRevert(bytes("evaluator address prediction: the deployer's nonce moved"));
        this.deployEvaluator(p);
    }

    function deployEvaluator(RemoteEvaluationDeploy.EvaluatorParams memory p) external {
        RemoteEvaluationDeploy.deployEvaluator(p, address(this));
    }

    function test_deploy_gatewayPreflight() public {
        RemoteEvaluationDeploy.GatewayParams memory p = _gatewayParams(makeAddr("predicted"));
        p.universalGateway = makeAddr("no code");
        vm.expectRevert(bytes("universalGateway: no code"));
        remoteSide.deploy(p);
        p = _gatewayParams(makeAddr("predicted"));
        p.layouts[0] = 3;
        vm.expectRevert(bytes("layout"));
        remoteSide.deploy(p);
    }

    function test_deploy_evaluatorPreflight_chainWithoutGasToken_andSenderCodeHash() public {
        address predicted = RemoteEvaluationDeploy.predictEvaluator(address(this));
        RemoteEvaluationDeploy.EvaluatorParams memory p = _evaluatorParams(address(gw), predicted);
        p.remotes[0].chainId = "1";
        vm.expectRevert(bytes("chain has no gas token"));
        this.deployEvaluator(p);
        p = _evaluatorParams(address(gw), predicted);
        p.remotes[0].senderCodeHash = bytes32(0);
        vm.expectRevert(bytes("sender code hash: zero"));
        this.deployEvaluator(p);
    }

    /// @notice The script reads its settings from the environment and checks deployed contracts against them.
    function test_script_checksAgainstEnvironment() public {
        (EvaluationGateway g, RemoteEvaluator r) = _deployAll();
        DeployRemoteEvaluationScript script = new DeployRemoteEvaluationScript();

        vm.setEnv("UNIVERSAL_GATEWAY", vm.toString(address(ugw)));
        vm.setEnv("REMOTE_EVALUATOR", vm.toString(address(r)));
        vm.setEnv("FEE_RECIPIENT", vm.toString(feeRecipient));
        vm.setEnv("PROXY_ADMIN_OWNER", vm.toString(proxyAdminOwner));
        vm.setEnv("READ_GAS", vm.toString(READ_GAS));
        vm.setEnv("MIN_SETTLE_WINDOW", vm.toString(SETTLE_WINDOW));
        vm.setEnv("MAX_CONFIRMATIONS", "64");
        vm.setEnv("KERNELS", vm.toString(kernel_()));
        vm.setEnv("LAYOUTS", "1");
        vm.setEnv("GATEWAY", vm.toString(address(g)));
        script.checkGateway();

        vm.setEnv("UEA_FACTORY", vm.toString(address(ueaFactory)));
        vm.setEnv("UNIVERSAL_GATEWAY_PC", vm.toString(address(ugpc)));
        vm.setEnv("READ_STATE", vm.toString(address(readState)));
        vm.setEnv("UNIVERSAL_CORE", vm.toString(address(core)));
        vm.setEnv("READ_TTL", "300");
        vm.setEnv("CALLBACK_GAS_LIMIT", "1000000");
        vm.setEnv("SNAPSHOT_CALLBACK_GAS_LIMIT", "300000");
        vm.setEnv("BUDGET_MULTIPLIER", "3");
        vm.setEnv("MAX_HEIGHT_AGE", "3600");
        vm.setEnv("REMOTE_CHAIN_IDS", CHAIN);
        vm.setEnv("REMOTE_GATEWAYS", vm.toString(address(g)));
        vm.setEnv("SETTLE_GAS_LIMITS", vm.toString(uint256(SETTLE_GAS)));
        vm.setEnv("SENDER_CODE_HASHES", vm.toString(g.senderCodeHash()));
        script.checkEvaluator();
        vm.setEnv("SENDER_CODE_HASHES", vm.toString(keccak256("another build")));
        vm.expectRevert(bytes("evaluator: sender code hash"));
        script.checkEvaluator();

        vm.setEnv("READ_GAS", "1"); // a setting that doesn't match what was deployed
        vm.expectRevert(bytes("gateway: settings"));
        script.checkGateway();
    }
}
