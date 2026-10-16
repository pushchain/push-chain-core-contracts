// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalEvaluatorDeploy} from "../../scripts/agentic-commerce-8183/UniversalEvaluatorDeploy.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";

/// @notice The deploy route, through the same library the deploy script runs: the hook proxy and the evaluator
///         deployed together and checked (step 1), the hook whitelisted (step 2), then a job evaluated through them.
contract UniversalEvaluatorDeployTest is UniversalEvalBase {
    UniversalEvaluatorDeploy.Params internal params;
    UniversalEvaluatorDeploy.Deployed internal deployed;

    function setUp() public override {
        super.setUp(); // the fixture's own pair, replaced below
        params = UniversalEvaluatorDeploy.Params({
            kernel: address(kernel),
            agwFactory: address(factory),
            sessionEngine: address(engine),
            hookAdminOwner: proxyAdminOwner,
            readState: address(readState),
            universalCore: address(core),
            feeRecipient: feeRecipient,
            config: _config()
        });
        deployed = UniversalEvaluatorDeploy.deploy(params, address(this)); // step 1
        hook = deployed.hook;
        ue = deployed.evaluator;
    }

    /// @dev Unusable until the kernel admin whitelists the hook; then a swap job runs end to end through the pair.
    function test_UD01_deploy_whitelist_thenEvaluates() public {
        assertFalse(kernel.whitelistedHooks(address(hook)));
        vm.startPrank(admin);
        UniversalEvaluatorDeploy.whitelist(params, deployed); // step 2
        vm.stopPrank();
        assertTrue(kernel.whitelistedHooks(address(hook)));

        uint256 jobId = _submittedSwap(0);
        _answer(jobId, 0, abi.encode(uint256(0.4e18)));
        assertEq(uint8(_status(jobId)), uint8(IAgenticCommerce.JobStatus.Completed));
    }

    /// @dev The proxy was initialised in its constructor, with the evaluator: nobody can initialise it again.
    function test_UD02_hookCannotBeInitialisedAgain() public {
        vm.prank(stranger);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        hook.initialize(address(kernel), address(factory), address(engine), stranger);
        assertEq(hook.EVALUATOR(), address(ue));
    }

    /// @dev `check` refuses a pair that isn't wired together, or a proxy someone else controls.
    function test_UD03_checkRefusesAMismatchedPair() public {
        UniversalEvaluatorDeploy.Deployed memory other = deployed;
        other.evaluator =
            _newEvaluator(address(kernel), address(hook), address(readState), address(core), feeRecipient, _config());
        vm.expectRevert(bytes("hook: evaluator"));
        this.checkWith(params, other);

        UniversalEvaluatorDeploy.Params memory wrong = params;
        wrong.hookAdminOwner = stranger;
        vm.expectRevert(bytes("hook: proxy admin owner"));
        this.checkWith(wrong, deployed);
    }

    /// @dev The evaluator is bound to its dependencies for good, so a Read State missing a view it calls is refused.
    function test_UD04_refusesMissingDependencies() public {
        UniversalEvaluatorDeploy.Params memory wrong = params;
        wrong.readState = address(kernel); // no isDomainBlocked
        vm.expectRevert(bytes("read state: no isDomainBlocked"));
        this.deployWith(wrong);
    }

    /// @dev The call the script prints for a multisig kernel admin does the same as step 2.
    function test_UD05_printedWhitelistCall_matchesStep2() public {
        (address target, bytes memory data) = UniversalEvaluatorDeploy.whitelistCall(params, deployed);
        assertEq(target, address(kernel));
        vm.prank(admin);
        (bool ok,) = target.call(data);
        assertTrue(ok);
        assertTrue(kernel.whitelistedHooks(address(hook)));
    }

    /// @dev External so `expectRevert` sees the library's revert as a call.
    function deployWith(UniversalEvaluatorDeploy.Params memory p) external {
        UniversalEvaluatorDeploy.deploy(p, address(this));
    }

    function checkWith(UniversalEvaluatorDeploy.Params memory p, UniversalEvaluatorDeploy.Deployed memory d)
        external
        view
    {
        UniversalEvaluatorDeploy.check(p, d);
    }
}
