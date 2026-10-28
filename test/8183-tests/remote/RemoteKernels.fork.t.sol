// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {
    JobSpec,
    Read,
    Check,
    Logic,
    Evaluation,
    Operation,
    LogicKind,
    AllowedMutability,
    ReadAt,
    T_TUPLE,
    T_UINT
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {EvaluationGateway} from "../../../src/agentic-commerce-8183/remote/EvaluationGateway.sol";
import {NoopHook} from "../../../src/agentic-commerce-8183/remote/NoopHook.sol";
import {
    PushFees,
    LAYOUT_V,
    LAYOUT_R,
    IEvaluationGateway,
    IUniversalGatewayVault,
    IVaultCEAFactory,
    VERDICT_PASS,
    VERIFY_SLOT
} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";

interface IVirtualsKernel {
    function createJob(
        address provider,
        address evaluator,
        uint256 expiredAt,
        string calldata description,
        address hook
    ) external returns (uint256);
    function setBudget(uint256 jobId, uint256 amount, bytes calldata optParams) external;
    function fund(uint256 jobId, uint256 expectedBudget, bytes calldata optParams) external;
    function submit(uint256 jobId, bytes32 deliverable, bytes calldata optParams) external;
    function paymentToken() external view returns (address);
}

interface ICEAFactoryDeploy {
    function deployCEA(address pushAccount) external returns (address);
    function getCEAForPushAccount(address pushAccount) external view returns (address, bool);
}

/// @notice Phase 0 on forks: the gateway against the kernels and gateway contracts deployed today.
///         - Base Sepolia: Virtuals `AgenticCommerceV3` (layout V, no hook), the live UniversalGateway, Vault, CEA.
///         - BSC testnet: APEX `AgenticCommerceUpgradeable` (layout R, NoopHook), the live UniversalGateway, Vault, CEA.
///         Each run: create → fund → snapshot → work → submit → verify (a real `sendUniversalTx`) → the Vault deploys
///         the RemoteEvaluator's CEA and the CEA calls `settle` → `complete`. Gas of each step is logged.
/// @dev - Network-dependent: skipped when the RPC can't be reached. `BASE_SEPOLIA_RPC_URL` / `BSC_TESTNET_RPC_URL`
///        override the public endpoints.
///      - The Vault is impersonated for the last leg (TSS signs `finalizeUniversalTx` in production, which adds the
///        Vault's own overhead on top of what is measured here).
contract RemoteKernelsForkTest is Test {
    // Base Sepolia
    address constant VIRTUALS = 0x0b93793923CD5De81850aF8604a233f3f24d461e;
    address constant BASE_UGW = 0xFD4fef1F43aFEc8b5bcdEEc47f35a1431479aC16;
    address constant EUSDC = 0x7Bc4b4f37d9f86454BB84b1c79cd4b4321bF2111; // the Phase 1 live run's dummy USDC
    address constant AUSDC = 0x55664A1E7956D74AFb0060ad6C6A55C005D64d7d; // its Aave aToken
    // BSC testnet
    address constant APEX = 0xa206c0517B6371C6638CD9e4a42Cc9f02A33B0DE;
    address constant BSC_UGW = 0x44aFFC61983F4348DdddB886349eb992C061EaC0;
    address constant APEX_USDC = 0xc70B8741B8B07A6d61E54fd4B20f22Fa648E5565;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal pushEvaluator = makeAddr("RemoteEvaluator on Push");
    address internal feeRecipient = makeAddr("feeRecipient");
    uint256 internal constant BUDGET = 1_000e6;

    NoopHook internal noop;
    EvaluationGateway internal gw;

    function _fork(string memory envName, string memory fallbackUrl) internal returns (bool) {
        string memory url = vm.envOr(envName, fallbackUrl);
        try vm.createSelectFork(url) returns (uint256) {
            return true;
        } catch {
            vm.skip(true);
            return false;
        }
    }

    function _deployGateway(address ugw, address kernel, uint8 layout) internal {
        noop = new NoopHook();
        address[] memory kernels = new address[](1);
        kernels[0] = kernel;
        uint8[] memory layouts = new uint8[](1);
        layouts[0] = layout;
        EvaluationGateway impl = new EvaluationGateway();
        gw = EvaluationGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(impl),
                        makeAddr("proxyAdminOwner"),
                        abi.encodeCall(
                            EvaluationGateway.initialize,
                            (EvaluationGateway.Config({
                                    universalGateway: ugw,
                                    remoteEvaluator: pushEvaluator,
                                    noopHook: address(noop),
                                    feeRecipient: feeRecipient,
                                    readGas: 200_000,
                                    minSettleWindow: 15 minutes,
                                    maxConfirmations: 64,
                                    kernels: kernels,
                                    layouts: layouts
                                }))
                        )
                    )
                ))
        );
    }

    function _read(address target, address account, ReadAt at) internal view returns (Read memory) {
        uint8[] memory field = new uint8[](1);
        return Read({
            chainNamespace: "eip155",
            chainId: vm.toString(block.chainid),
            minConfirmations: 3,
            target: target,
            selector: IERC20.balanceOf.selector,
            args: abi.encode(account),
            outputs: abi.encodePacked(T_TUPLE, uint8(1), T_UINT),
            field: field,
            at: at
        });
    }

    /// @notice Four reads, two NUMBER checks under ALL: the running example's shape.
    function _spec(address a, address b) internal view returns (JobSpec memory s) {
        s.reads = new Read[](4);
        s.reads[0] = _read(a, alice, ReadAt.POST_EXECUTION);
        s.reads[1] = _read(b, alice, ReadAt.POST_EXECUTION);
        s.reads[2] = _read(a, alice, ReadAt.PRE_EXECUTION);
        s.reads[3] = _read(b, alice, ReadAt.PRE_EXECUTION);
        uint8[] memory l0 = new uint8[](1);
        uint8[] memory r0 = new uint8[](1);
        uint8[] memory l1 = new uint8[](1);
        uint8[] memory r1 = new uint8[](1);
        l0[0] = 0;
        r0[0] = 2;
        l1[0] = 1;
        r1[0] = 3;
        s.checks = new Check[](2);
        s.checks[0] = Check({
            left: l0, right: r0, evaluation: Evaluation.NUMBER, operation: Operation.GREATER_OR_EQUAL, target: 600e6
        });
        s.checks[1] = Check({
            left: l1, right: r1, evaluation: Evaluation.NUMBER, operation: Operation.GREATER_OR_EQUAL, target: 0
        });
        uint8[] memory children = new uint8[](2);
        children[0] = 1;
        children[1] = 2;
        s.logic = new Logic[](3);
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        s.logic[1] = Logic({kind: LogicKind.COMPARE, check: 0, children: new uint8[](0), k: 0});
        s.logic[2] = Logic({kind: LogicKind.COMPARE, check: 1, children: new uint8[](0), k: 0});
        s.allowedMutability = AllowedMutability.NONE;
    }

    function _snapshot(address kernel, uint256 jobId) internal returns (bytes[] memory pre) {
        vm.recordLogs();
        vm.prank(alice);
        uint256 g = gasleft();
        gw.snapshot(kernel, jobId, PushFees(0, 0, 0));
        console2.log("  snapshot gas:", g - gasleft());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == EvaluationGateway.Snapshotted.selector) {
                (,, pre) = abi.decode(logs[i].data, (bytes32, uint64, bytes[]));
            }
        }
    }

    function _verify(address kernel, uint256 jobId, JobSpec memory s, bytes[] memory pre, address ugw) internal {
        vm.roll(block.number + 1);
        vm.deal(bob, 1 ether);
        vm.recordLogs();
        vm.prank(bob);
        uint256 g = gasleft();
        gw.verify{value: 0.001 ether}(kernel, jobId, abi.encode(s), pre, PushFees(0.5 ether, 5_000_000, 10 gwei));
        console2.log("  verify gas (incl. sendUniversalTx):", g - gasleft());
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        address sender = gw.senderOf(kernel, jobId, VERIFY_SLOT);
        assertGt(sender.code.length, 0, "the verify sender was deployed");
        for (uint256 i; i < logs.length; ++i) {
            // UniversalTx(address indexed sender, ...) from the live gateway, sender = the job's verify sender
            if (
                logs[i].emitter == ugw && logs[i].topics.length > 1
                    && address(uint160(uint256(logs[i].topics[1]))) == sender
            ) {
                seen = true;
            }
        }
        assertTrue(seen, "the live UniversalGateway emitted the inbound with the job's verify sender as sender");
    }

    /// @notice The last leg as the Vault runs it: deploy the evaluator's CEA (first time), then the CEA calls `settle`.
    function _settle(address ugw, address kernel, uint256 jobId) internal {
        address vault = IUniversalGatewayVault(ugw).VAULT();
        address factory = IVaultCEAFactory(vault).CEAFactory();
        (address cea, bool deployed) = ICEAFactoryDeploy(factory).getCEAForPushAccount(pushEvaluator);
        if (!deployed) {
            vm.prank(vault);
            uint256 g0 = gasleft();
            cea = ICEAFactoryDeploy(factory).deployCEA(pushEvaluator);
            console2.log("  CEA deploy gas (first verdict on this chain):", g0 - gasleft());
        }
        bytes32 key = gw.captureKeyOf(kernel, jobId);
        bytes memory payload = abi.encodeCall(IEvaluationGateway.settle, (kernel, jobId, key, true, bytes32("r")));
        vm.prank(vault);
        uint256 g = gasleft();
        (bool ok,) = cea.call(
            abi.encodeWithSignature(
                "executeUniversalTx(bytes32,bytes32,address,address,bytes)",
                keccak256(abi.encode("sub", jobId)),
                keccak256(abi.encode("utx", jobId)),
                pushEvaluator,
                address(gw),
                payload
            )
        );
        console2.log("  CEA.executeUniversalTx -> settle -> complete gas:", g - gasleft());
        assertTrue(ok, "CEA call");
        EvaluationGateway.Record memory r = gw.recordOf(kernel, jobId);
        assertEq(r.verdict, VERDICT_PASS);
        assertTrue(r.applied, "the kernel completed the job");
    }

    function test_fork_virtuals_baseSepolia() public {
        if (!_fork("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org")) return;
        console2.log("Virtuals AgenticCommerceV3 on Base Sepolia, block", block.number);
        _deployGateway(BASE_UGW, VIRTUALS, LAYOUT_V);
        IVirtualsKernel k = IVirtualsKernel(VIRTUALS);
        JobSpec memory s = _spec(EUSDC, AUSDC);
        bytes memory description = abi.encode(s);
        console2.log("  description bytes:", description.length);

        vm.prank(alice);
        uint256 g = gasleft();
        uint256 jobId = k.createJob(bob, address(gw), block.timestamp + 2 hours, string(description), address(0));
        console2.log("  createJob gas:", g - gasleft());
        vm.prank(bob);
        k.setBudget(jobId, BUDGET, "");
        address payToken = k.paymentToken();
        deal(payToken, alice, BUDGET);
        vm.prank(alice);
        IERC20(payToken).approve(VIRTUALS, BUDGET);
        vm.prank(alice);
        k.fund(jobId, BUDGET, "");

        assertEq(gw.jobOf(VIRTUALS, jobId).evaluator, address(gw), "layout V decodes the live kernel");
        bytes[] memory pre = _snapshot(VIRTUALS, jobId);
        assertEq(pre.length, 4);

        deal(EUSDC, alice, IERC20(EUSDC).balanceOf(alice) + 600e6); // Bob's work
        vm.prank(bob);
        k.submit(jobId, keccak256("deliverable"), "");
        _verify(VIRTUALS, jobId, s, pre, BASE_UGW);

        uint256 before = IERC20(payToken).balanceOf(bob);
        _settle(BASE_UGW, VIRTUALS, jobId);
        assertGt(IERC20(payToken).balanceOf(bob), before, "Bob paid");
        uint256 evalFee = IERC20(payToken).balanceOf(address(gw));
        console2.log("  evaluator fee paid to the gateway:", evalFee);
        gw.sweep(payToken);
        assertEq(IERC20(payToken).balanceOf(feeRecipient), evalFee);
    }

    function test_fork_apex_bscTestnet() public {
        if (!_fork("BSC_TESTNET_RPC_URL", "https://bsc-testnet-rpc.publicnode.com")) return;
        console2.log("APEX AgenticCommerceUpgradeable on BSC testnet, block", block.number);
        _deployGateway(BSC_UGW, APEX, LAYOUT_R);
        IVirtualsKernel k = IVirtualsKernel(APEX); // same createJob / setBudget / fund / submit signatures
        address other = address(new BalanceToken());
        JobSpec memory s = _spec(APEX_USDC, other);
        bytes memory description = abi.encode(s);

        vm.prank(alice);
        uint256 g = gasleft();
        uint256 jobId = k.createJob(bob, address(gw), block.timestamp + 2 hours, string(description), address(noop));
        console2.log("  createJob gas (NoopHook passes APEX's ERC-165 check):", g - gasleft());
        vm.prank(alice);
        k.setBudget(jobId, BUDGET, "");
        deal(APEX_USDC, alice, BUDGET);
        vm.prank(alice);
        IERC20(APEX_USDC).approve(APEX, BUDGET);
        vm.prank(alice);
        k.fund(jobId, BUDGET, "");

        assertEq(gw.jobOf(APEX, jobId).evaluator, address(gw), "layout R decodes the live kernel");
        assertEq(gw.jobOf(APEX, jobId).hook, address(noop));
        bytes[] memory pre = _snapshot(APEX, jobId);

        deal(APEX_USDC, alice, IERC20(APEX_USDC).balanceOf(alice) + 600e6); // Bob's work
        vm.prank(bob);
        k.submit(jobId, keccak256("deliverable"), "");
        _verify(APEX, jobId, s, pre, BSC_UGW);

        uint256 before = IERC20(APEX_USDC).balanceOf(bob);
        _settle(BSC_UGW, APEX, jobId);
        assertEq(IERC20(APEX_USDC).balanceOf(bob), before + BUDGET, "Bob paid in full (no fees on this kernel)");
    }
}

/// @notice A second balance target for the BSC run.
contract BalanceToken {
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }
}
