// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {UniversalEvaluatorDeploy} from "./UniversalEvaluatorDeploy.sol";
import {UniversalEvaluator} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluator.sol";
import {UniversalEvaluatorLogic} from "../../src/agentic-commerce-8183/evaluator/UniversalEvaluatorLogic.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {ReadConfig} from "../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/**
 * @title DeployUniversalEvaluatorScript
 * @notice Ships the UniversalEvaluator by upgrading the existing RulesBindingHook proxy in place
 *         (see `UniversalEvaluatorDeploy` for the three steps).
 *
 * @dev Precondition: the JobSpec layout is final. The evaluator is not upgradeable and decodes the layout it was
 *      compiled with.
 *
 *      Every address and setting comes from the environment; nothing has a default:
 *        KERNEL, HOOK_PROXY, EXPECTED_HOOK_IMPL (the RulesBindingHook implementation the proxy runs today),
 *        READ_STATE, UNIVERSAL_CORE, FEE_RECIPIENT,
 *        READ_TTL, CALLBACK_GAS_LIMIT, SNAPSHOT_CALLBACK_GAS_LIMIT, BUDGET_MULTIPLIER, MAX_HEIGHT_AGE, MAX_CONFIRMATIONS
 *      MAX_HEIGHT_AGE gates every `fund` and `submit`: set it above the slowest tracked chain's update interval.
 *      MAX_CONFIRMATIONS caps every read's confirmations: the slowest supported chain must reach it well within
 *      READ_TTL and a job's expiry.
 *
 *      Step 1, any deployer:
 *        forge script scripts/agentic-commerce-8183/deployUniversalEvaluator.s.sol --rpc-url $RPC_URL --broadcast
 *      Prints the evaluator and hook implementation addresses, and the step-2 call for a multisig.
 *
 *      Step 2, the hook's ProxyAdmin owner (skip if the multisig sends the printed call instead):
 *        EVALUATOR=0x.. LOGIC=0x.. HOOK_IMPL=0x.. forge script ... --sig "upgrade()" --rpc-url $RPC_URL --broadcast
 *
 *      Step 3, the marketplace admin: `UniversalMarketplace.setEvaluator(EVALUATOR)`, only once the marketplace builds
 *      the final JobSpec and the SDK sends the new `fund` params. Before that, every marketplace `fund` would revert.
 */
contract DeployUniversalEvaluatorScript is Script {
    function run() external {
        UniversalEvaluatorDeploy.Params memory p = _params();
        vm.startBroadcast();
        UniversalEvaluatorDeploy.Deployed memory d = UniversalEvaluatorDeploy.deploy(p);
        vm.stopBroadcast();

        (address target, bytes memory data) = UniversalEvaluatorDeploy.upgradeCall(p, d);
        console.log("=== UniversalEvaluator deployed (step 1) ===");
        console.log("Logic:", address(d.logic));
        console.log("Evaluator:", address(d.evaluator));
        console.log("UniversalHook implementation:", address(d.hookImpl));
        console.log("Step 2: the ProxyAdmin owner sends this call to", target);
        console.logBytes(data);
        console.log(
            "Step 3, only after the marketplace builds the final JobSpec and the SDK sends the new fund params:"
        );
        console.log("  the marketplace admin calls setEvaluator with the evaluator address");
    }

    function upgrade() external {
        UniversalEvaluatorDeploy.Params memory p = _params();
        UniversalEvaluatorDeploy.Deployed memory d = UniversalEvaluatorDeploy.Deployed({
            logic: UniversalEvaluatorLogic(vm.envAddress("LOGIC")),
            evaluator: UniversalEvaluator(vm.envAddress("EVALUATOR")),
            hookImpl: UniversalHook(vm.envAddress("HOOK_IMPL"))
        });
        UniversalEvaluatorDeploy.checkEvaluator(p, d);
        vm.startBroadcast();
        UniversalEvaluatorDeploy.upgrade(p, d);
        vm.stopBroadcast();
        console.log("=== Hook upgraded in place (step 2) ===");
        console.log("Hook proxy:", p.hookProxy);
        console.log("Evaluator:", address(d.evaluator));
        console.log(
            "Step 3, only after the marketplace builds the final JobSpec and the SDK sends the new fund params:"
        );
        console.log("  the marketplace admin calls setEvaluator with the evaluator address");
    }

    function _params() internal view returns (UniversalEvaluatorDeploy.Params memory p) {
        p.kernel = vm.envAddress("KERNEL");
        p.hookProxy = vm.envAddress("HOOK_PROXY");
        p.expectedHookImpl = vm.envAddress("EXPECTED_HOOK_IMPL");
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
