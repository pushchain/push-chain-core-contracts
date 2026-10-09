// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    TransparentUpgradeableProxy,
    ITransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalEvaluatorDeploy} from "../../scripts/agentic-commerce-8183/UniversalEvaluatorDeploy.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {RulesBindingHook} from "../../src/agentic-commerce-8183/hooks/RulesBindingHook.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {UniversalHookErrors, UniversalEvaluatorErrors} from "../../src/agentic-commerce-8183/libraries/Errors.sol";

/// @notice The in-place route: the live RulesBindingHook proxy becomes the UniversalHook, through the same library the
///         deploy script runs. Starts from today's state (the RulesBindingHook proxy, whitelisted), deploys the
///         evaluator pointing at that proxy (step 1), and upgrades in each test (step 2).
contract UniversalHookMigrationTest is UniversalEvalBase {
    address internal interimEvaluator = makeAddr("interimEvaluator");
    RulesBindingHook internal rbImpl;
    UniversalEvaluatorDeploy.Params internal params;
    UniversalEvaluatorDeploy.Deployed internal deployed;

    /// @dev What is live today: RulesBindingHook behind its proxy. `hook` is typed as the UniversalHook it becomes.
    function _deployPair() internal override {
        rbImpl = new RulesBindingHook();
        hook = UniversalHook(
            address(
                new TransparentUpgradeableProxy(
                    address(rbImpl),
                    proxyAdminOwner,
                    abi.encodeCall(RulesBindingHook.initialize, (address(kernel), address(factory), address(engine)))
                )
            )
        );
    }

    function setUp() public override {
        super.setUp(); // whitelists the proxy on the kernel, as it is today
        params = UniversalEvaluatorDeploy.Params({
            kernel: address(kernel),
            hookProxy: address(hook),
            expectedHookImpl: address(rbImpl),
            readState: address(readState),
            universalCore: address(core),
            feeRecipient: feeRecipient,
            config: _config()
        });
        deployed = UniversalEvaluatorDeploy.deploy(params); // step 1
        ue = deployed.evaluator;
        logic = deployed.logic;
    }

    /// @notice A job under the interim setup: the interim evaluator, RulesBindingHook's 32-byte fund params.
    function _interimJob() internal returns (uint256 jobId) {
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, interimEvaluator, _expiry(), "interim", address(hook)))
        );
        jobId = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(jobId, BUDGET, "");
        _fundWith(jobId, abi.encode(RULES));
    }

    function _upgrade() internal {
        vm.startPrank(proxyAdminOwner);
        UniversalEvaluatorDeploy.upgrade(params, deployed); // step 2: upgradeAndCall + initializeV2, then checks
        vm.stopPrank();
    }

    /// @dev A wallet's binding and its live interim job survive the upgrade; the interim job finishes as before; the
    ///      next job is evaluated by the new evaluator through the same proxy address.
    function test_UM01_inPlaceUpgrade_keepsBindings_thenEvaluates() public {
        uint256 interim = _interimJob();
        (address boundAgw, bytes32 boundRules) = hook.rulesOf(interim);
        assertEq(boundAgw, address(agw));
        assertEq(boundRules, RULES);
        assertTrue(hook.isAGWBusy(address(agw)));

        _upgrade();

        assertEq(hook.EVALUATOR(), address(ue));
        (address agwAfter, bytes32 rulesAfter) = hook.rulesOf(interim);
        assertEq(agwAfter, boundAgw, "binding kept");
        assertEq(rulesAfter, boundRules, "binding kept");
        assertEq(hook.liveJobOf(address(agw)), interim, "live job kept");
        assertTrue(hook.isAGWBusy(address(agw)), "one live job per wallet still enforced");

        // The interim job is not ours: the upgraded hook leaves it to its own evaluator.
        vm.prank(provider);
        kernel.submit(interim, keccak256("done"), "");
        assertFalse(ue.evaluationOf(interim).endFixed);
        vm.prank(interimEvaluator);
        kernel.complete(interim, bytes32(0), "");
        assertFalse(hook.isAGWBusy(address(agw)));

        // A new job through the same proxy is evaluated end to end.
        uint256 jobId = _submittedSwap(0);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev Upgraded without the call, the proxy has no evaluator, and only its admin can set one, once.
    function test_UM02_initializeV2_onlyThroughUpgrade_once() public {
        ProxyAdmin pa = ProxyAdmin(UniversalEvaluatorDeploy.proxyAdminOf(address(hook)));
        vm.prank(proxyAdminOwner);
        pa.upgradeAndCall(ITransparentUpgradeableProxy(address(hook)), address(deployed.hookImpl), "");
        assertEq(hook.EVALUATOR(), address(0), "nothing evaluated until initializeV2");

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalHookErrors.CallerIsNotProxyAdmin.selector, stranger));
        hook.initializeV2(stranger);

        bytes memory init = abi.encodeCall(UniversalHook.initializeV2, (address(ue)));
        vm.prank(proxyAdminOwner);
        pa.upgradeAndCall(ITransparentUpgradeableProxy(address(hook)), address(deployed.hookImpl), init);
        assertEq(hook.EVALUATOR(), address(ue));

        vm.prank(proxyAdminOwner);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pa.upgradeAndCall(ITransparentUpgradeableProxy(address(hook)), address(deployed.hookImpl), init);
    }

    /// @dev The script refuses a proxy that is not running the expected RulesBindingHook implementation.
    function test_UM04_refusesUnexpectedImplementation() public {
        UniversalEvaluatorDeploy.Params memory wrong = params;
        wrong.expectedHookImpl = address(new RulesBindingHook()); // same code, different deployment
        vm.expectRevert(bytes("hook proxy: not the expected RulesBindingHook implementation"));
        this.deployWith(wrong);
    }

    /// @dev External so `expectRevert` sees the library's revert as a call.
    function deployWith(UniversalEvaluatorDeploy.Params memory p) external {
        UniversalEvaluatorDeploy.deploy(p);
    }

    /// @dev The call the script prints for a multisig ProxyAdmin owner does the same upgrade.
    function test_UM03_printedUpgradeCall_matchesUpgrade() public {
        (address target, bytes memory data) = UniversalEvaluatorDeploy.upgradeCall(params, deployed);
        assertEq(target, UniversalEvaluatorDeploy.proxyAdminOf(address(hook)));
        vm.prank(proxyAdminOwner);
        (bool ok,) = target.call(data);
        assertTrue(ok);
        assertEq(hook.EVALUATOR(), address(ue));
    }

    /// @dev Why `initializeV2` exists. The design's plan is to upgrade this proxy in place, but `initialize` already ran
    ///      on it, so a plain upgrade leaves `EVALUATOR` zero. The hook then treats every job as "not ours": a job
    ///      naming the evaluator is funded, but its spec is never frozen and no snapshot is taken, and `submit`
    ///      doesn't reach the evaluator either. The job can never be judged.
    function test_UM05_withoutInitializeV2_jobsAreNeverEvaluated() public {
        ProxyAdmin pa = ProxyAdmin(UniversalEvaluatorDeploy.proxyAdminOf(address(hook)));
        vm.prank(proxyAdminOwner);
        pa.upgradeAndCall(ITransparentUpgradeableProxy(address(hook)), address(deployed.hookImpl), "");
        assertEq(hook.EVALUATOR(), address(0));

        uint256 jobId = _createSpec(_swapSpec()); // names `ue` as its evaluator
        (uint256 snap, uint256 eval_) = ue.prefundCost(jobId);
        _prefund(jobId, snap + eval_);
        bytes memory fp = _fundParams(jobId);
        _fundWith(jobId, fp);
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Funded), "funded");
        assertFalse(ue.cacheOf(jobId).frozen, "but the spec never reached the evaluator");
        assertFalse(ue.ready(jobId));

        _advance();
        _submit(jobId);
        assertFalse(ue.evaluationOf(jobId).endFixed, "and neither did submit");
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(UniversalEvaluatorErrors.WrongStatus.selector, jobId));
        ue.sendReads(jobId);
    }
}
