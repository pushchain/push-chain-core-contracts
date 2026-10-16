// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {
    JobSpec,
    Read,
    Check,
    Logic,
    LogicKind,
    Evaluation,
    Operation,
    ReadAt,
    AllowedMutability,
    T_TUPLE,
    T_UINT
} from "../../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";
import {UniversalAccountId, Multicall, MULTICALL_SELECTOR} from "../../../src/libraries/Types.sol";

/// @title E2E — what the evaluator end-to-end scripts share: fixed addresses, state files, keys and the job's spec.
/// @dev State lives in `deployments/e2e-evaluator/` (gitignored): one JSON per chain, one for the current job.
library E2E {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant PUSH_DONUT_CHAIN_ID = 42101;
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    /// @notice Donut predeploys: Read State (UniversalCallback proxy) and UniversalCore (tracked heights, read fees).
    address internal constant READ_STATE = 0x00000000000000000000000000000000000000c2;
    address internal constant UNIVERSAL_CORE = 0x00000000000000000000000000000000000000C0;
    /// @notice Donut's UEA factory (predeploy) and Base Sepolia's CEA factory (`CEA_FACTORY()` of its gateway).
    address internal constant UEA_FACTORY = 0x00000000000000000000000000000000000000eA;
    address internal constant CEA_FACTORY = 0x7e8CeeDA043ED1460540616103dD57581a66C856;
    /// @notice Push's outbound gateway (UniversalGatewayPC predeploy) and the PRC20 it charges Base Sepolia gas in.
    address internal constant GATEWAY_PC = 0x00000000000000000000000000000000000000C1;
    address internal constant PETH_BASE = 0xc7007af2B24D4eb963fc9633B0c66e1d2D90Fc21;

    string internal constant NS = "eip155";
    string internal constant BASE_ID = "84532";
    string internal constant BASE_KEY = "eip155:84532";

    /// @notice Any rules id: the allow-all stand-in accepts every one.
    bytes32 internal constant RULES_ID = keccak256("e2e-evaluator-rules");

    /// @notice Where the state files live; `E2E_STATE_DIR` overrides it (must stay under `deployments/`).
    function dir() internal view returns (string memory) {
        return VM.envOr("E2E_STATE_DIR", string("deployments/e2e-evaluator"));
    }

    function _file(string memory name) private view returns (string memory) {
        return string.concat(dir(), "/", name);
    }

    struct BaseAddrs {
        address usdc;
        address aavePool;
        address aToken;
        address morphoVault;
    }

    /// @notice Who the job is for. EOA mode: the client key's address on both chains. UEA mode
    ///         (`CLIENT_MODE=uea`): the job's client is that key's UEA on Push, and the reads measure the UEA's CEA.
    struct Accounts {
        bool uea;
        address owner; // the client key's address
        address client; // the job's client on Push
        address measured; // the account the reads measure on Base Sepolia
    }

    struct PushAddrs {
        address kernel;
        address paymentToken;
        address allowAll;
        address hook;
        address evaluator;
    }

    // ───────── keys and settings ─────────

    function clientKey() internal view returns (uint256) {
        return VM.envUint("CLIENT_PRIVATE_KEY");
    }

    function providerKey() internal view returns (uint256) {
        return VM.envUint("PROVIDER_PRIVATE_KEY");
    }

    /// @notice The client key's address: the job's client in EOA mode, the UEA's owner in UEA mode.
    function client() internal view returns (address) {
        return VM.addr(clientKey());
    }

    /// @notice Sends the UEA's signed payloads (anyone may) and pays for UEA-mode steps; defaults to the client key.
    function relayerKey() internal view returns (uint256) {
        return VM.envOr("RELAYER_PRIVATE_KEY", clientKey());
    }

    function ueaMode() internal view returns (bool) {
        return keccak256(bytes(VM.envOr("CLIENT_MODE", string("eoa")))) == keccak256("uea");
    }

    /// @notice The UEA's origin: the client key on `UEA_ORIGIN_CHAIN_ID` (default Base Sepolia), an EVM chain Donut's
    ///         UEA factory has registered.
    function ueaOrigin() internal view returns (UniversalAccountId memory) {
        return UniversalAccountId({
            chainNamespace: NS,
            chainId: VM.envOr("UEA_ORIGIN_CHAIN_ID", string(BASE_ID)),
            owner: abi.encodePacked(client())
        });
    }

    function provider() internal view returns (address) {
        return VM.addr(providerKey());
    }

    /// @notice What the client asks for (6 decimals); the job passes if at least 99.99% of it arrives.
    function total() internal view returns (uint256) {
        return VM.envOr("ALLOC_TOTAL", uint256(1000e6));
    }

    // ───────── state files ─────────

    /// @notice Only a broadcast writes state: a dry run's addresses were never deployed, and `run.sh all` skips
    ///         deploying when the files exist.
    function _persist() private view returns (bool) {
        return VM.isContext(VmSafe.ForgeContext.ScriptBroadcast) || VM.isContext(VmSafe.ForgeContext.ScriptResume);
    }

    function saveBase(BaseAddrs memory b) internal {
        if (!_persist()) return;
        VM.createDir(dir(), true);
        string memory k = "base";
        VM.serializeAddress(k, "usdc", b.usdc);
        VM.serializeAddress(k, "aavePool", b.aavePool);
        VM.serializeAddress(k, "aToken", b.aToken);
        VM.writeJson(VM.serializeAddress(k, "morphoVault", b.morphoVault), _file("base-sepolia.json"));
    }

    function loadBase() internal view returns (BaseAddrs memory b) {
        string memory j = VM.readFile(_file("base-sepolia.json"));
        b.usdc = VM.parseJsonAddress(j, ".usdc");
        b.aavePool = VM.parseJsonAddress(j, ".aavePool");
        b.aToken = VM.parseJsonAddress(j, ".aToken");
        b.morphoVault = VM.parseJsonAddress(j, ".morphoVault");
    }

    function savePush(PushAddrs memory p, address hookImpl, address kernelImpl) internal {
        if (!_persist()) return;
        VM.createDir(dir(), true);
        string memory k = "push";
        VM.serializeAddress(k, "kernel", p.kernel);
        VM.serializeAddress(k, "kernelImpl", kernelImpl);
        VM.serializeAddress(k, "paymentToken", p.paymentToken);
        VM.serializeAddress(k, "allowAll", p.allowAll);
        VM.serializeAddress(k, "hookImpl", hookImpl);
        VM.serializeAddress(k, "hook", p.hook);
        VM.serializeAddress(k, "readState", READ_STATE);
        VM.serializeAddress(k, "universalCore", UNIVERSAL_CORE);
        VM.writeJson(VM.serializeAddress(k, "evaluator", p.evaluator), _file("push.json"));
    }

    function loadPush() internal view returns (PushAddrs memory p) {
        string memory j = VM.readFile(_file("push.json"));
        p.kernel = VM.parseJsonAddress(j, ".kernel");
        p.paymentToken = VM.parseJsonAddress(j, ".paymentToken");
        p.allowAll = VM.parseJsonAddress(j, ".allowAll");
        p.hook = VM.parseJsonAddress(j, ".hook");
        p.evaluator = VM.parseJsonAddress(j, ".evaluator");
    }

    function saveAccounts(Accounts memory a) internal {
        if (!_persist()) return;
        VM.createDir(dir(), true);
        string memory k = "accounts";
        VM.serializeBool(k, "uea", a.uea);
        VM.serializeAddress(k, "owner", a.owner);
        VM.serializeAddress(k, "client", a.client);
        VM.writeJson(VM.serializeAddress(k, "measured", a.measured), _file("accounts.json"));
    }

    /// @notice The accounts `accounts` resolved, checked against this run's mode and client key.
    function loadAccounts() internal view returns (Accounts memory a) {
        string memory j = VM.readFile(_file("accounts.json"));
        a.uea = VM.parseJsonBool(j, ".uea");
        a.owner = VM.parseJsonAddress(j, ".owner");
        a.client = VM.parseJsonAddress(j, ".client");
        a.measured = VM.parseJsonAddress(j, ".measured");
        require(a.uea == ueaMode(), "accounts.json is for the other CLIENT_MODE: run `accounts` again");
        require(a.owner == client(), "accounts.json is for another CLIENT_PRIVATE_KEY: run `accounts` again");
    }

    function saveJob(uint256 id, bytes32 specHash, address jobClient, address measured) internal {
        if (!_persist()) return;
        string memory k = "job";
        VM.serializeUint(k, "jobId", id);
        VM.serializeAddress(k, "client", jobClient);
        VM.serializeAddress(k, "measured", measured);
        VM.serializeAddress(k, "provider", provider());
        VM.writeJson(VM.serializeBytes32(k, "specHash", specHash), _file("job.json"));
    }

    /// @notice The account the job's reads measure, as `open` recorded it.
    function jobMeasured() internal view returns (address) {
        return VM.parseJsonAddress(VM.readFile(_file("job.json")), ".measured");
    }

    /// @notice `JOB_ID` from the environment, else the job `open` recorded.
    function jobId() internal view returns (uint256) {
        uint256 fromEnv = VM.envOr("JOB_ID", uint256(0));
        if (fromEnv != 0) return fromEnv;
        return VM.parseJsonUint(VM.readFile(_file("job.json")), ".jobId");
    }

    // ───────── the job ─────────

    /// @notice "Allocate `total` USDC across Aave and Morpho for `account`", on Base Sepolia:
    ///         reads 0 / 1: aUSDC balance and Morpho position after the job (POST);
    ///         reads 2 / 3: the same before it (PRE, at the block recorded at `fund`);
    ///         check 0: (aUSDC + Morpho) after − (aUSDC + Morpho) before ≥ 99.99% of `total`;
    ///         checks 1 / 2: each venue grew. All three must pass.
    function allocationSpec(BaseAddrs memory b, address account, uint256 total_, uint16 minConfirmations)
        internal
        view
        returns (JobSpec memory s)
    {
        s.executeBy = uint64(block.timestamp + 1 hours); // not used by the evaluator
        s.failFinalAt = uint64(block.timestamp + 2 hours);
        s.reads = new Read[](4);
        s.reads[0] = _read(b.aToken, IERC20.balanceOf.selector, account, ReadAt.POST_EXECUTION, minConfirmations);
        s.reads[1] =
            _read(b.morphoVault, IERC4626.maxWithdraw.selector, account, ReadAt.POST_EXECUTION, minConfirmations);
        s.reads[2] = _read(b.aToken, IERC20.balanceOf.selector, account, ReadAt.PRE_EXECUTION, minConfirmations);
        s.reads[3] =
            _read(b.morphoVault, IERC4626.maxWithdraw.selector, account, ReadAt.PRE_EXECUTION, minConfirmations);

        s.checks = new Check[](3);
        s.checks[0] = Check({
            left: _idx(0, 1),
            right: _idx(2, 3),
            evaluation: Evaluation.NUMBER,
            operation: Operation.GREATER_OR_EQUAL,
            target: int256(total_ * 9999 / 10_000)
        });
        s.checks[1] = Check({left: _idx(0), right: _idx(2), evaluation: Evaluation.NUMBER, operation: Operation.GREATER_THAN, target: 0});
        s.checks[2] = Check({left: _idx(1), right: _idx(3), evaluation: Evaluation.NUMBER, operation: Operation.GREATER_THAN, target: 0});

        s.logic = new Logic[](4);
        uint8[] memory children = new uint8[](3);
        (children[0], children[1], children[2]) = (1, 2, 3);
        s.logic[0] = Logic({kind: LogicKind.ALL, check: 0, children: children, k: 0});
        for (uint8 i; i < 3; ++i) {
            s.logic[1 + i] = Logic({kind: LogicKind.CHECK, check: i, children: new uint8[](0), k: 0});
        }
        s.allowedMutability = AllowedMutability.NONE;
        s.origin = keccak256("e2e-evaluator");
    }

    /// @notice The CEA's own work, as the multicall it runs on Base Sepolia when the outbound lands: approve + supply
    ///         to Aave, approve + deposit to Morpho, both for the CEA. `MULTICALL_SELECTOR ‖ abi.encode(Multicall[])`.
    function ceaAllocationPayload(BaseAddrs memory b, address cea, uint256 toAave, uint256 toMorpho)
        internal
        pure
        returns (bytes memory)
    {
        Multicall[] memory calls = new Multicall[]((toAave != 0 ? 2 : 0) + (toMorpho != 0 ? 2 : 0));
        uint256 i;
        if (toAave != 0) {
            calls[i++] = Multicall({to: b.usdc, value: 0, data: abi.encodeCall(IERC20.approve, (b.aavePool, toAave))});
            calls[i++] = Multicall({
                to: b.aavePool,
                value: 0,
                data: abi.encodeWithSignature("supply(address,uint256,address,uint16)", b.usdc, toAave, cea, uint16(0))
            });
        }
        if (toMorpho != 0) {
            calls[i++] =
                Multicall({to: b.usdc, value: 0, data: abi.encodeCall(IERC20.approve, (b.morphoVault, toMorpho))});
            calls[i++] =
                Multicall({to: b.morphoVault, value: 0, data: abi.encodeCall(IERC4626.deposit, (toMorpho, cea))});
        }
        return abi.encodePacked(MULTICALL_SELECTOR, abi.encode(calls));
    }

    function _read(address target, bytes4 selector, address account, ReadAt at, uint16 minConfirmations)
        private
        pure
        returns (Read memory r)
    {
        r.chainNamespace = NS;
        r.chainId = BASE_ID;
        r.minConfirmations = minConfirmations;
        r.target = target;
        r.selector = selector;
        r.args = abi.encode(account);
        r.outputs = abi.encodePacked(T_TUPLE, uint8(1), T_UINT);
        r.field = new uint8[](1); // the first return value
        r.at = at;
    }

    function _idx(uint8 a) private pure returns (uint8[] memory x) {
        x = new uint8[](1);
        x[0] = a;
    }

    function _idx(uint8 a, uint8 b) private pure returns (uint8[] memory x) {
        x = new uint8[](2);
        (x[0], x[1]) = (a, b);
    }
}
