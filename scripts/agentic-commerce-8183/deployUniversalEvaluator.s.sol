// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {UniversalEvaluatorDeploy} from "./UniversalEvaluatorDeploy.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/**
 * @title DeployUniversalEvaluatorScript
 * @notice Deploys the UniversalHook and the UniversalEvaluator together (see `UniversalEvaluatorDeploy` for the three
 *         steps).
 *
 * @dev Precondition: the JobSpec layout is final. The evaluator is not upgradeable and decodes the layout it was
 *      compiled with.
 *
 *      Every address and setting comes from the environment; nothing has a default:
 *        KERNEL, AGW_FACTORY, SESSION_ENGINE, HOOK_ADMIN_OWNER (owns the hook proxy's ProxyAdmin),
 *        READ_STATE, UNIVERSAL_CORE, FEE_RECIPIENT,
 *        READ_TTL, CALLBACK_GAS_LIMIT, SNAPSHOT_CALLBACK_GAS_LIMIT, BUDGET_MULTIPLIER, MAX_HEIGHT_AGE, MAX_CONFIRMATIONS
 *      MAX_HEIGHT_AGE gates every `fund` and `submit`: set it above the slowest tracked chain's update interval.
 *      MAX_CONFIRMATIONS caps every read's confirmations: the slowest supported chain must reach it well within
 *      READ_TTL and a job's expiry.
 *
 *      Step 1, any deployer:
 *        forge script scripts/agentic-commerce-8183/deployUniversalEvaluator.s.sol --rpc-url $RPC_URL --broadcast
 *      Prints the hook, its implementation and the evaluator, and the step-2 call for a multisig.
 *
 *      Step 2, the kernel admin (skip if the multisig sends the printed call instead):
 *        HOOK=0x.. EVALUATOR=0x.. forge script ... --sig "whitelist()" --rpc-url $RPC_URL --broadcast
 *
 *      Step 3, the marketplace admin: `UniversalMarketplace.setHook(HOOK)` and `setEvaluator(EVALUATOR)`, only once the
 *      marketplace builds the final JobSpec and the SDK sends the new `fund` params. Before that, every marketplace
 *      `fund` would revert.
 */
contract DeployUniversalEvaluatorScript is Script {
    function run() external {
        UniversalEvaluatorDeploy.Params memory p = _params();
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        UniversalEvaluatorDeploy.Deployed memory d = UniversalEvaluatorDeploy.deploy(p, deployer);
        vm.stopBroadcast();

        (address target, bytes memory data) = UniversalEvaluatorDeploy.whitelistCall(p, d);
        console.log("=== UniversalHook and UniversalEvaluator deployed (step 1) ===");
        console.log("Hook (proxy):", address(d.hook));
        console.log("Hook implementation:", address(d.hookImpl));
        console.log("Evaluator:", address(d.evaluator));
        console.log("Step 2: the kernel admin sends this call to", target);
        console.logBytes(data);
        _logStep3();
    }

    function whitelist() external {
        UniversalEvaluatorDeploy.Params memory p = _params();
        UniversalHook hook = UniversalHook(vm.envAddress("HOOK"));
        UniversalEvaluatorDeploy.Deployed memory d = UniversalEvaluatorDeploy.Deployed({
            hook: hook,
            hookImpl: UniversalHook(UniversalEvaluatorDeploy.implementationOf(address(hook))),
            evaluator: UniversalEvaluator(vm.envAddress("EVALUATOR"))
        });
        vm.startBroadcast();
        UniversalEvaluatorDeploy.whitelist(p, d);
        vm.stopBroadcast();
        console.log("=== Hook whitelisted on the kernel (step 2) ===");
        console.log("Hook (proxy):", address(d.hook));
        _logStep3();
    }

    function _logStep3() internal pure {
        console.log(
            "Step 3, only after the marketplace builds the final JobSpec and the SDK sends the new fund params:"
        );
        console.log("  the marketplace admin calls setHook with the hook and setEvaluator with the evaluator");
    }

    function _params() internal view returns (UniversalEvaluatorDeploy.Params memory p) {
        p.kernel = vm.envAddress("KERNEL");
        p.agwFactory = vm.envAddress("AGW_FACTORY");
        p.sessionEngine = vm.envAddress("SESSION_ENGINE");
        p.hookAdminOwner = vm.envAddress("HOOK_ADMIN_OWNER");
        p.readState = vm.envAddress("READ_STATE");
        p.universalCore = vm.envAddress("UNIVERSAL_CORE");
        p.feeRecipient = vm.envAddress("FEE_RECIPIENT");
        p.config = ReadConfig({
            readTtl: _envU64("READ_TTL"),
            callbackGasLimit: _envU64("CALLBACK_GAS_LIMIT"),
            snapshotCallbackGasLimit: _envU64("SNAPSHOT_CALLBACK_GAS_LIMIT"),
            budgetMultiplier: vm.envUint("BUDGET_MULTIPLIER"),
            maxHeightAge: vm.envUint("MAX_HEIGHT_AGE"),
            maxConfirmations: _envU16("MAX_CONFIRMATIONS")
        });
    }

    function _envU64(string memory name) internal view returns (uint64) {
        uint256 v = vm.envUint(name);
        require(v <= type(uint64).max, string.concat(name, " does not fit uint64"));
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v); // safe: checked above
    }

    function _envU16(string memory name) internal view returns (uint16) {
        uint256 v = vm.envUint(name);
        require(v <= type(uint16).max, string.concat(name, " does not fit uint16"));
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint16(v); // safe: checked above
    }
}
