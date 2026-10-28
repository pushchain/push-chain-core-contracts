// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalTxRequest} from "../../../src/interfaces/IUniversalGateway.sol";
import {UniversalAccountId} from "../../../src/libraries/Types.sol";
import {UniversalOutboundTxRequest, IKernelLayoutR} from "../../../src/agentic-commerce-8183/remote/RemoteTypes.sol";
import {MockReadCore} from "../mocks/MockReadCore.sol";

// ─────────────────────────────── remote chain ───────────────────────────────

/// @notice The remote chain's UniversalGateway: records every inbound, as the UVs would observe its event.
contract MockRemoteGateway {
    struct Sent {
        address sender;
        uint256 value;
        UniversalTxRequest req;
    }

    address public VAULT;
    Sent[] internal _sent;

    function setVault(address vault) external {
        VAULT = vault;
    }

    function sendUniversalTx(UniversalTxRequest calldata req) external payable {
        _sent.push(Sent({sender: msg.sender, value: msg.value, req: req}));
    }

    function count() external view returns (uint256) {
        return _sent.length;
    }

    function sent(uint256 i) external view returns (Sent memory) {
        return _sent[i];
    }
}

/// @notice The remote Vault's one getter the gateway follows.
contract MockRemoteVault {
    address public CEAFactory;

    constructor(address factory) {
        CEAFactory = factory;
    }
}

/// @notice The remote CEAFactory's reverse lookup.
contract MockCEAFactory {
    mapping(address => address) public getPushAccountForCEA;

    function set(address cea, address pushAccount) external {
        getPushAccountForCEA[cea] = pushAccount;
    }
}

/// @notice A token-like read target with settable balances.
contract MockBalances {
    mapping(address => uint256) public balanceOf;

    function set(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }
}

/// @notice A read target that always reverts.
contract RevertingTarget {
    function balanceOf(address) external pure returns (uint256) {
        revert("no");
    }
}

/// @notice A read target that returns 100 KB.
contract BombTarget {
    function balanceOf(address) external pure returns (uint256) {
        assembly {
            return(0, 100000)
        }
    }
}

/// @notice A read target that never finishes within any gas cap.
contract GasHungryTarget {
    function balanceOf(address) external pure returns (uint256) {
        assembly {
            for {} 1 {} {}
        }
        return 0;
    }
}

/// @notice A kernel with APEX's layout (layout R) and its two evaluator calls, with jobs set directly.
contract MockKernelR {
    mapping(uint256 => IKernelLayoutR.JobR) internal _jobs;
    uint256 public completed;
    uint256 public rejected;
    bool public heavy; // `complete` burns all the gas it gets: a kernel too heavy for the settle outbound

    function setHeavy(bool heavy_) external {
        heavy = heavy_;
    }

    function setJob(uint256 jobId, IKernelLayoutR.JobR memory job) external {
        _jobs[jobId] = job;
    }

    function setStatus(uint256 jobId, uint8 status) external {
        _jobs[jobId].status = status;
    }

    function getJob(uint256 jobId) external view returns (IKernelLayoutR.JobR memory) {
        return _jobs[jobId];
    }

    function complete(uint256 jobId, bytes32, bytes calldata) external {
        while (heavy) {}
        require(msg.sender == _jobs[jobId].evaluator && _jobs[jobId].status == 2, "complete");
        _jobs[jobId].status = 3;
        ++completed;
    }

    function reject(uint256 jobId, bytes32, bytes calldata) external {
        require(msg.sender == _jobs[jobId].evaluator, "reject");
        _jobs[jobId].status = 4;
        ++rejected;
    }
}

// ─────────────────────────────── Push ───────────────────────────────

/// @notice The UEA factory's origin lookup.
contract MockUEAFactory {
    mapping(address => UniversalAccountId) internal _origins;
    mapping(address => bool) internal _isUEA;

    function setOrigin(address uea, string calldata ns, string calldata chainId, bytes calldata owner) external {
        _origins[uea] = UniversalAccountId({chainNamespace: ns, chainId: chainId, owner: owner});
        _isUEA[uea] = true;
    }

    function getOriginForUEA(address addr) external view returns (UniversalAccountId memory, bool) {
        return (_origins[addr], _isUEA[addr]);
    }

    /// @notice A deterministic address per origin, as the real factory's CREATE2 prediction is.
    function computeUEA(UniversalAccountId memory id) external pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode("uea", id.chainNamespace, id.chainId, id.owner)))));
    }
}

/// @notice UniversalCore: Read State's views plus the gas-token lookup.
contract MockRemoteCore is MockReadCore {
    mapping(string => address) public gasTokenPRC20ByChainNamespace;

    function setGasToken(string calldata chainKey, address token) external {
        gasTokenPRC20ByChainNamespace[chainKey] = token;
    }
}

/// @notice UniversalGatewayPC: takes `fee` PC per outbound and refunds the rest to the caller in the same call, as
///         the deployed contract does. Checks what the deployed contract checks on the fields the evaluator sets.
contract MockUGPC {
    struct Out {
        address sender;
        uint256 value;
        UniversalOutboundTxRequest req;
    }

    uint256 public fee;
    uint256 public baseGasLimit = 500_000;
    Out[] internal _outs;

    function setFee(uint256 f) external {
        fee = f;
    }

    function sendUniversalTxOutbound(UniversalOutboundTxRequest calldata req) external payable {
        require(req.token != address(0), "ZeroAddress");
        require(req.revertRecipient != address(0), "InvalidRecipient");
        require(req.gasLimit >= baseGasLimit, "GasLimitBelowBase");
        require(msg.value >= fee, "fee");
        _outs.push(Out({sender: msg.sender, value: msg.value, req: req}));
        uint256 back = msg.value - fee;
        if (back > 0) {
            (bool ok,) = msg.sender.call{value: back}("");
            require(ok, "refund");
        }
    }

    function count() external view returns (uint256) {
        return _outs.length;
    }

    function out(uint256 i) external view returns (Out memory) {
        return _outs[i];
    }
}
