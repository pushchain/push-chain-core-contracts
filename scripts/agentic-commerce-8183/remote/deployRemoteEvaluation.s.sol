// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {RemoteEvaluationDeploy} from "./RemoteEvaluationDeploy.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {ReadConfig} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";

/**
 * @title DeployRemoteEvaluationScript
 * @notice Deploys Phase 2 in three steps (see `RemoteEvaluationDeploy`). Every address and setting comes from the
 *         environment; nothing has a default.
 *
 *         Step 1, on Push: where the RemoteEvaluator will land. The deployer then sends nothing else on Push until step 3.
 *           DEPLOYER=0x.. forge script scripts/agentic-commerce-8183/remote/deployRemoteEvaluation.s.sol \
 *             --sig "predict()" --rpc-url $PUSH_RPC_URL
 *
 *         Step 2, on each remote chain, with REMOTE_EVALUATOR = the step-1 address:
 *           UNIVERSAL_GATEWAY, REMOTE_EVALUATOR, FEE_RECIPIENT, PROXY_ADMIN_OWNER, READ_GAS, MIN_SETTLE_WINDOW,
 *           MAX_CONFIRMATIONS, KERNELS (comma-separated), LAYOUTS (comma-separated: 1 = Virtuals / Push layout,
 *           2 = ERC reference / APEX layout)
 *           forge script ... --sig "deployGateway()" --rpc-url $REMOTE_RPC_URL --broadcast
 *           GATEWAY=0x.. forge script ... --sig "checkGateway()" --rpc-url $REMOTE_RPC_URL
 *
 *         Step 3, on Push, from the step-1 deployer:
 *           UEA_FACTORY, UNIVERSAL_GATEWAY_PC, READ_STATE, UNIVERSAL_CORE, PROXY_ADMIN_OWNER,
 *           READ_TTL, CALLBACK_GAS_LIMIT, SNAPSHOT_CALLBACK_GAS_LIMIT, BUDGET_MULTIPLIER, MAX_HEIGHT_AGE,
 *           MAX_CONFIRMATIONS (the same as every gateway's), REMOTE_CHAIN_IDS (decimal, comma-separated),
 *           REMOTE_GATEWAYS (the step-2 proxies, same order), SETTLE_GAS_LIMITS (same order; at least each chain's
 *           base gas limit), SENDER_CODE_HASHES (each gateway's `senderCodeHash()`, printed in step 2, same order),
 *           REMOTE_EVALUATOR (the step-1 address)
 *           forge script ... --sig "deployEvaluator()" --rpc-url $PUSH_RPC_URL --broadcast
 *           forge script ... --sig "checkEvaluator()" --rpc-url $PUSH_RPC_URL
 */
contract DeployRemoteEvaluationScript is Script {
    function predict() external view {
        address deployer = vm.envAddress("DEPLOYER");
        console.log("Push deployer:", deployer);
        console.log("Its nonce now:", vm.getNonce(deployer));
        console.log("RemoteEvaluator (proxy) will be at:", RemoteEvaluationDeploy.predictEvaluator(deployer));
    }

    function deployGateway() external {
        RemoteEvaluationDeploy.GatewayParams memory p = _gatewayParams();
        vm.startBroadcast();
        RemoteEvaluationDeploy.GatewayDeployed memory d = RemoteEvaluationDeploy.deployGateway(p);
        vm.stopBroadcast();
        console.log("=== EvaluationGateway deployed on chain", block.chainid, "===");
        console.log("EvaluationGateway (proxy):", address(d.gateway));
        console.log("EvaluationGateway implementation:", address(d.gatewayImpl));
        console.log("NoopHook:", address(d.noopHook));
        console.log("Sender code hash:", vm.toString(d.gateway.senderCodeHash()));
        console.log("Pass the proxy in REMOTE_GATEWAYS and the hash in SENDER_CODE_HASHES for step 3.");
    }

    function checkGateway() external view {
        RemoteEvaluationDeploy.checkGateway(EvaluationGateway(payable(vm.envAddress("GATEWAY"))), _gatewayParams());
        console.log("EvaluationGateway wiring: ok");
    }

    function deployEvaluator() external {
        RemoteEvaluationDeploy.EvaluatorParams memory p = _evaluatorParams();
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        RemoteEvaluationDeploy.EvaluatorDeployed memory d = RemoteEvaluationDeploy.deployEvaluator(p, deployer);
        vm.stopBroadcast();
        console.log("=== RemoteEvaluator deployed on Push ===");
        console.log("RemoteEvaluator (proxy):", address(d.evaluator));
        console.log("RemoteEvaluator implementation:", address(d.evaluatorImpl));
    }

    function checkEvaluator() external view {
        RemoteEvaluationDeploy.EvaluatorParams memory p = _evaluatorParams();
        RemoteEvaluationDeploy.checkEvaluator(RemoteEvaluator(payable(p.expected)), p);
        console.log("RemoteEvaluator wiring: ok");
    }

    function _gatewayParams() internal view returns (RemoteEvaluationDeploy.GatewayParams memory p) {
        uint256[] memory layouts = vm.envUint("LAYOUTS", ",");
        p.universalGateway = vm.envAddress("UNIVERSAL_GATEWAY");
        p.remoteEvaluator = vm.envAddress("REMOTE_EVALUATOR");
        p.feeRecipient = vm.envAddress("FEE_RECIPIENT");
        p.proxyAdminOwner = vm.envAddress("PROXY_ADMIN_OWNER");
        p.readGas = vm.envUint("READ_GAS");
        p.minSettleWindow = vm.envUint("MIN_SETTLE_WINDOW");
        p.maxConfirmations = _u16(vm.envUint("MAX_CONFIRMATIONS"));
        p.kernels = vm.envAddress("KERNELS", ",");
        p.layouts = new uint8[](layouts.length);
        for (uint256 i; i < layouts.length; ++i) {
            require(layouts[i] <= type(uint8).max, "LAYOUTS");
            // forge-lint: disable-next-line(unsafe-typecast)
            p.layouts[i] = uint8(layouts[i]); // safe: checked above
        }
    }

    function _evaluatorParams() internal view returns (RemoteEvaluationDeploy.EvaluatorParams memory p) {
        string[] memory ids = vm.envString("REMOTE_CHAIN_IDS", ",");
        address[] memory gateways = vm.envAddress("REMOTE_GATEWAYS", ",");
        uint256[] memory gas = vm.envUint("SETTLE_GAS_LIMITS", ",");
        bytes32[] memory codeHashes = vm.envBytes32("SENDER_CODE_HASHES", ",");
        require(
            ids.length == gateways.length && ids.length == gas.length && ids.length == codeHashes.length,
            "remote lists differ in length"
        );
        p.ueaFactory = vm.envAddress("UEA_FACTORY");
        p.universalGatewayPC = vm.envAddress("UNIVERSAL_GATEWAY_PC");
        p.readState = vm.envAddress("READ_STATE");
        p.universalCore = vm.envAddress("UNIVERSAL_CORE");
        p.proxyAdminOwner = vm.envAddress("PROXY_ADMIN_OWNER");
        p.expected = vm.envAddress("REMOTE_EVALUATOR");
        p.read = ReadConfig({
            readTtl: _u64(vm.envUint("READ_TTL")),
            callbackGasLimit: _u64(vm.envUint("CALLBACK_GAS_LIMIT")),
            snapshotCallbackGasLimit: _u64(vm.envUint("SNAPSHOT_CALLBACK_GAS_LIMIT")),
            budgetMultiplier: vm.envUint("BUDGET_MULTIPLIER"),
            maxHeightAge: vm.envUint("MAX_HEIGHT_AGE"),
            maxConfirmations: _u16(vm.envUint("MAX_CONFIRMATIONS"))
        });
        p.remotes = new RemoteEvaluator.Remote[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            p.remotes[i] = RemoteEvaluator.Remote({
                chainId: ids[i], gateway: gateways[i], settleGasLimit: _u64(gas[i]), senderCodeHash: codeHashes[i]
            });
        }
    }

    function _u64(uint256 v) internal pure returns (uint64) {
        require(v <= type(uint64).max, "value above uint64");
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(v); // safe: checked above
    }

    function _u16(uint256 v) internal pure returns (uint16) {
        require(v <= type(uint16).max, "value above uint16");
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint16(v); // safe: checked above
    }
}
