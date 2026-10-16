// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {E2E} from "./E2EConfig.sol";
import {E2EPaymentToken, E2EAllowAll} from "./E2EMocks.sol";
import {UniversalEvaluatorDeploy} from "../UniversalEvaluatorDeploy.sol";
import {AgenticCommerce} from "../../../src/agentic-commerce-8183/AgenticCommerce.sol";
import {ReadConfig} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/// @title E2EPushDeploy — the Push Chain side of the evaluator end-to-end run (see README.md)
/// @notice One broadcaster (`--private-key`), which becomes the kernel admin, the proxies' admin owner and the fee
///         recipient. Deploys the payment token, the allow-all stand-in, the kernel behind a proxy, then the
///         UniversalHook and UniversalEvaluator through `UniversalEvaluatorDeploy` (steps 1 and 2) against Donut's
///         live Read State and UniversalCore.
/// @dev Evaluator settings come from the environment, with defaults for Donut (~2.45 s blocks):
///      READ_TTL 1200 Push blocks (~49 min) · CALLBACK_GAS_LIMIT 1,000,000 · SNAPSHOT_CALLBACK_GAS_LIMIT 300,000 ·
///      BUDGET_MULTIPLIER 3 · MAX_HEIGHT_AGE 600 s · MAX_CONFIRMATIONS 64.
contract E2EPushDeploy is Script {
    function run() external {
        require(block.chainid == E2E.PUSH_DONUT_CHAIN_ID, "E2EPushDeploy: not Push Donut (42101)");
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();

        E2EPaymentToken token = new E2EPaymentToken();
        E2EAllowAll allowAll = new E2EAllowAll();
        AgenticCommerce kernelImpl = new AgenticCommerce();
        AgenticCommerce kernel = AgenticCommerce(
            address(
                new TransparentUpgradeableProxy(
                    address(kernelImpl),
                    deployer,
                    abi.encodeCall(AgenticCommerce.initialize, (address(token), deployer, deployer))
                )
            )
        );

        UniversalEvaluatorDeploy.Params memory p = UniversalEvaluatorDeploy.Params({
            kernel: address(kernel),
            agwFactory: address(allowAll),
            sessionEngine: address(allowAll),
            hookAdminOwner: deployer,
            readState: E2E.READ_STATE,
            universalCore: E2E.UNIVERSAL_CORE,
            feeRecipient: deployer,
            config: _config()
        });
        UniversalEvaluatorDeploy.Deployed memory d = UniversalEvaluatorDeploy.deploy(p, deployer);
        UniversalEvaluatorDeploy.whitelist(p, d); // the deployer is the kernel admin
        vm.stopBroadcast();

        E2E.savePush(
            E2E.PushAddrs({
                kernel: address(kernel),
                paymentToken: address(token),
                allowAll: address(allowAll),
                hook: address(d.hook),
                evaluator: address(d.evaluator)
            }),
            address(d.hookImpl),
            address(kernelImpl)
        );
        console.log("=== Push Donut: kernel, hook and evaluator deployed ===");
        console.log("Kernel (proxy):     ", address(kernel));
        console.log("Payment token:      ", address(token));
        console.log("Allow-all AGW/rules:", address(allowAll));
        console.log("Hook (proxy):       ", address(d.hook));
        console.log("Evaluator:          ", address(d.evaluator));
        console.log("Admin / fee recipient:", deployer);
    }

    function _config() internal view returns (ReadConfig memory) {
        return ReadConfig({
            readTtl: uint64(vm.envOr("READ_TTL", uint256(1200))),
            callbackGasLimit: uint64(vm.envOr("CALLBACK_GAS_LIMIT", uint256(1_000_000))),
            snapshotCallbackGasLimit: uint64(vm.envOr("SNAPSHOT_CALLBACK_GAS_LIMIT", uint256(300_000))),
            budgetMultiplier: vm.envOr("BUDGET_MULTIPLIER", uint256(3)),
            maxHeightAge: vm.envOr("MAX_HEIGHT_AGE", uint256(600)),
            maxConfirmations: uint16(vm.envOr("MAX_CONFIRMATIONS", uint256(64)))
        });
    }
}
