// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {RemoteEvaluator} from "../../../src/agentic-commerce-8183/remote/RemoteEvaluator.sol";
import {NoopHook} from "../../../src/agentic-commerce-8183/remote/NoopHook.sol";
import {ReadConfig} from "../../../src/agentic-commerce-8183/evaluator/EvaluationTypes.sol";
import {
    LAYOUT_V,
    LAYOUT_R,
    IUniversalGatewayVault,
    IVaultCEAFactory,
    IRemoteCore,
    IReadStateModule
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";

/// @title RemoteEvaluationDeploy — deploys Phase 2: one EvaluationGateway per remote chain, then the RemoteEvaluator on
///        Push; shared by the deploy script and its test
/// @notice Each side needs the other's address. The gateways need the RemoteEvaluator's, so it is predicted from the
///         Push deployer's nonce (its implementation takes the next nonce, its proxy the one after):
///         1. on Push, `predictEvaluator(deployer)` gives the address; the deployer sends nothing else on Push until
///            step 3;
///         2. on each remote chain, `deployGateway` (NoopHook, gateway implementation, gateway proxy), recorded with its
///            `senderCodeHash()`;
///         3. on Push, `deployEvaluator` with every gateway and its sender code hash; it reverts unless the proxy lands
///            on the predicted address.
/// @dev - Every step checks its inputs and its result and reverts on a mismatch; a wrong prediction reverts in the
///        script's simulation, before anything is sent.
///      - `maxConfirmations` must be the same on every gateway and on the RemoteEvaluator, so both sides validate the
///        criteria alike. The scripts read it from one variable.
///      - `JobSpecLib` is a linked library: forge deploys and links it with the gateway implementation on each remote
///        chain, as it does for the UniversalEvaluator on Push.
library RemoteEvaluationDeploy {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct GatewayParams {
        address universalGateway; // this chain's UniversalGateway
        address remoteEvaluator; // predicted in step 1
        address feeRecipient;
        address proxyAdminOwner; // owns the gateway proxy's ProxyAdmin
        uint256 readGas;
        uint256 minSettleWindow;
        uint16 maxConfirmations;
        address[] kernels;
        uint8[] layouts;
    }

    struct GatewayDeployed {
        EvaluationGateway gateway; // the proxy
        EvaluationGateway gatewayImpl;
        NoopHook noopHook;
    }

    struct EvaluatorParams {
        address ueaFactory;
        address universalGatewayPC;
        address readState;
        address universalCore;
        address proxyAdminOwner; // owns the RemoteEvaluator proxy's ProxyAdmin
        ReadConfig read;
        RemoteEvaluator.Remote[] remotes;
        address expected; // the address predicted in step 1, which every gateway was deployed with
    }

    struct EvaluatorDeployed {
        RemoteEvaluator evaluator; // the proxy
        RemoteEvaluator evaluatorImpl;
    }

    /// @notice Step 1: where `deployEvaluator` will put the RemoteEvaluator proxy when `deployer` runs it next.
    function predictEvaluator(address deployer) internal view returns (address) {
        return VM.computeCreateAddress(deployer, VM.getNonce(deployer) + 1);
    }

    /// @notice Step 2, on one remote chain.
    function deployGateway(GatewayParams memory p) internal returns (GatewayDeployed memory d) {
        _requireCode(p.universalGateway, "universalGateway");
        address vault = IUniversalGatewayVault(p.universalGateway).VAULT();
        _requireCode(vault, "vault");
        _requireCode(IVaultCEAFactory(vault).CEAFactory(), "CEA factory");
        require(p.remoteEvaluator != address(0), "remoteEvaluator: zero");
        require(p.kernels.length != 0 && p.kernels.length == p.layouts.length, "kernels / layouts");
        for (uint256 i; i < p.kernels.length; ++i) {
            _requireCode(p.kernels[i], "kernel");
            require(p.layouts[i] == LAYOUT_V || p.layouts[i] == LAYOUT_R, "layout");
        }

        d.noopHook = new NoopHook();
        d.gatewayImpl = new EvaluationGateway();
        d.gateway = EvaluationGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(d.gatewayImpl),
                        p.proxyAdminOwner,
                        abi.encodeCall(
                            EvaluationGateway.initialize,
                            (EvaluationGateway.Config({
                                    universalGateway: p.universalGateway,
                                    remoteEvaluator: p.remoteEvaluator,
                                    noopHook: address(d.noopHook),
                                    feeRecipient: p.feeRecipient,
                                    readGas: p.readGas,
                                    minSettleWindow: p.minSettleWindow,
                                    maxConfirmations: p.maxConfirmations,
                                    kernels: p.kernels,
                                    layouts: p.layouts
                                }))
                        )
                    )
                ))
        );
        checkGateway(d.gateway, p);
    }

    /// @notice Step 3, on Push, from the deployer predicted in step 1.
    function deployEvaluator(EvaluatorParams memory p, address deployer) internal returns (EvaluatorDeployed memory d) {
        _requireCode(p.ueaFactory, "ueaFactory");
        _requireCode(p.universalGatewayPC, "universalGatewayPC");
        _requireCode(p.readState, "readState");
        _requireCode(p.universalCore, "universalCore");
        require(IReadStateModule(p.readState).UNIVERSAL_CALLBACK_MODULE() != address(0), "readState: no module");
        require(p.remotes.length != 0, "no remote chains");
        for (uint256 i; i < p.remotes.length; ++i) {
            string memory key = string.concat("eip155:", p.remotes[i].chainId);
            require(
                IRemoteCore(p.universalCore).gasTokenPRC20ByChainNamespace(key) != address(0), "chain has no gas token"
            );
            require(p.remotes[i].senderCodeHash != bytes32(0), "sender code hash: zero");
        }
        require(predictEvaluator(deployer) == p.expected, "evaluator address prediction: the deployer's nonce moved");

        d.evaluatorImpl = new RemoteEvaluator();
        d.evaluator = RemoteEvaluator(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(d.evaluatorImpl),
                        p.proxyAdminOwner,
                        abi.encodeCall(
                            RemoteEvaluator.initialize,
                            (RemoteEvaluator.Config({
                                    ueaFactory: p.ueaFactory,
                                    universalGatewayPC: p.universalGatewayPC,
                                    readState: p.readState,
                                    universalCore: p.universalCore,
                                    read: p.read,
                                    remotes: p.remotes
                                }))
                        )
                    )
                ))
        );
        require(address(d.evaluator) == p.expected, "evaluator address prediction");
        checkEvaluator(d.evaluator, p);
    }

    /// @notice A deployed gateway is wired as `p` says. Run after step 2, and again any time.
    function checkGateway(EvaluationGateway g, GatewayParams memory p) internal view {
        require(address(g.UGW()) == p.universalGateway, "gateway: UGW");
        require(g.REMOTE_EVALUATOR() == p.remoteEvaluator, "gateway: REMOTE_EVALUATOR");
        require(g.FEE_RECIPIENT() == p.feeRecipient, "gateway: FEE_RECIPIENT");
        require(g.READ_GAS() == p.readGas && g.MIN_SETTLE_WINDOW() == p.minSettleWindow, "gateway: settings");
        require(g.MAX_CONFIRMATIONS() == p.maxConfirmations, "gateway: MAX_CONFIRMATIONS");
        require(g.NOOP_HOOK().code.length != 0, "gateway: NOOP_HOOK");
        for (uint256 i; i < p.kernels.length; ++i) {
            require(g.layoutOf(p.kernels[i]) == p.layouts[i], "gateway: layout");
        }
        require(_admin(address(g)) != address(0), "gateway: not a proxy");
    }

    /// @notice A deployed RemoteEvaluator is wired as `p` says. Run after step 3, and again any time.
    function checkEvaluator(RemoteEvaluator re, EvaluatorParams memory p) internal view {
        require(address(re.UEA_FACTORY()) == p.ueaFactory, "evaluator: UEA_FACTORY");
        require(address(re.UGPC()) == p.universalGatewayPC, "evaluator: UGPC");
        require(address(re.READ_STATE()) == p.readState, "evaluator: READ_STATE");
        require(address(re.UNIVERSAL_CORE()) == p.universalCore, "evaluator: UNIVERSAL_CORE");
        require(re.CALLBACK_MODULE() == IReadStateModule(p.readState).UNIVERSAL_CALLBACK_MODULE(), "evaluator: module");
        require(re.MAX_CONFIRMATIONS() == p.read.maxConfirmations, "evaluator: MAX_CONFIRMATIONS");
        for (uint256 i; i < p.remotes.length; ++i) {
            require(re.gatewayOf(p.remotes[i].chainId) == p.remotes[i].gateway, "evaluator: gateway");
            require(re.settleGasOf(p.remotes[i].chainId) == p.remotes[i].settleGasLimit, "evaluator: settle gas");
            require(
                re.senderCodeHashOf(p.remotes[i].chainId) == p.remotes[i].senderCodeHash, "evaluator: sender code hash"
            );
        }
        require(_admin(address(re)) != address(0), "evaluator: not a proxy");
    }

    function _requireCode(address a, string memory what) private view {
        require(a.code.length != 0, string.concat(what, ": no code"));
    }

    function _admin(address proxy) private view returns (address) {
        return address(uint160(uint256(VM.load(proxy, ERC1967Utils.ADMIN_SLOT))));
    }
}
