// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {OwnerIntent} from "@push-agw/libraries/Types.sol";
import {Execution} from "@push-agw/libraries/ExecutionLib.sol";
import {Session} from "../../../src/agentic-commerce-8183/interfaces/external/IAGW.sol";
import {MockSmartSession} from "./MockSmartSession.sol";

interface IMockAGWFactoryEngine {
    function engine() external view returns (address);
}

/// @notice An AGW stand-in for UniversalMarketplace unit tests. OBSERVER, NOT ORACLE: it records what the marketplace
///         presented and runs the exec calldata so the REAL kernel runs `createJob` with this contract as
///         `msg.sender`. It checks the presenter and hashes like the real wallet, and verifies no signature. `mode`
///         lets a test make it misbehave in the ways the marketplace must catch.
/// @dev - `executeWithSig` runs ERC-7579 single or batch calldata; a batch entry targeting this wallet is a self-call,
///        so `grantRules` passes its owner-or-self check, as on the real wallet's owner door.
///      - `grantRules` mirrors AGW v6 `_grantRules` where the marketplace depends on it: the salt is overwritten with
///        the grant nonce, the id is `keccak256(abi.encode(validator, validatorInitData, salt))`, and the id is enabled
///        on the engine. It decodes the policy envelope as `(uint16, string, bytes)` exactly as the real policy does.
contract MockAGW {
    enum Mode {
        Honest,
        TwoJobs,
        ForeignClient,
        OtherEvaluator, // rewrites createJob's evaluator argument before calling the kernel
        SkipEnable // grants without enabling the id on the engine
    }

    address public constant OTHER_EVALUATOR = address(0xE7A1);
    bytes1 internal constant CALLTYPE_BATCH = 0x01;

    address public immutable OWNER;
    address public immutable FACTORY;
    Mode public mode;
    uint64 public grantNonce;
    mapping(uint192 => uint64) public getNonce;

    bytes32 public lastExecIntentHash;
    bytes32 public lastExecCalldataHash;
    bytes32 public lastExecMode;
    address public lastExecCaller;
    /// @notice The full policy `initData` of the last grant, for tests and the MI07 invariant to decode.
    bytes public lastPolicyInitData;
    /// @notice Every rules id granted, in order.
    bytes32[] public grantedIds;
    /// @notice Every grant's policy `initData`, in order (same index as `grantedIds`).
    bytes[] public grantedInitData;

    constructor(address owner_) {
        OWNER = owner_;
        FACTORY = msg.sender;
    }

    receive() external payable {}

    function setMode(Mode m) external {
        mode = m;
    }

    function SESSION_ENGINE() public view returns (address) {
        return IMockAGWFactoryEngine(FACTORY).engine();
    }

    function grantedCount() external view returns (uint256) {
        return grantedIds.length;
    }

    function grantRules(Session calldata session) external returns (bytes32 rulesId) {
        require(msg.sender == OWNER || msg.sender == address(this), "MockAGW: owner or self");
        bytes calldata initData = session.actions[0].actionPolicies[0].initData;
        abi.decode(initData, (uint16, string, bytes));
        rulesId = keccak256(
            abi.encode(session.sessionValidator, session.sessionValidatorInitData, bytes32(uint256(grantNonce)))
        );
        grantNonce++;
        if (mode != Mode.SkipEnable) MockSmartSession(SESSION_ENGINE()).setPermission(rulesId, address(this), true);
        lastPolicyInitData = initData;
        grantedIds.push(rulesId);
        grantedInitData.push(initData);
    }

    function executeWithSig(bytes32 execMode, bytes calldata cd, OwnerIntent calldata intent, bytes calldata) external {
        require(msg.sender == intent.executor, "MockAGW: executor");
        require(intent.mode == execMode, "MockAGW: mode");
        require(intent.execCalldataHash == keccak256(cd), "MockAGW: exec hash");
        require(intent.nonceSeq == getNonce[intent.nonceKey], "MockAGW: nonce");
        getNonce[intent.nonceKey]++;
        lastExecIntentHash = keccak256(abi.encode(intent));
        lastExecCalldataHash = keccak256(cd);
        lastExecMode = execMode;
        lastExecCaller = msg.sender;

        if (execMode[0] == CALLTYPE_BATCH) {
            Execution[] memory execs = abi.decode(cd, (Execution[]));
            for (uint256 i; i < execs.length; ++i) {
                _run(execs[i].target, execs[i].callData);
            }
        } else {
            _run(address(bytes20(cd[0:20])), cd[52:]);
        }
    }

    /// @dev Self-calls run as-is; the kernel call is where the misbehaviour modes apply.
    function _run(address target, bytes memory callData) internal {
        if (target == address(this)) {
            _call(target, callData);
            return;
        }
        if (mode == Mode.OtherEvaluator) {
            address other = OTHER_EVALUATOR;
            assembly ("memory-safe") {
                mstore(add(callData, 68), other) // data + 4 (selector) + 32 (provider) = the evaluator word
            }
        }
        if (mode == Mode.ForeignClient) {
            new ForeignCaller().forward(target, callData);
            return;
        }
        _call(target, callData);
        if (mode == Mode.TwoJobs) _call(target, callData);
    }

    function _call(address target, bytes memory data) internal {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

/// @dev Makes the call from a different address, so the kernel's `client` is not the AGW.
contract ForeignCaller {
    function forward(address target, bytes memory data) external {
        (bool ok,) = target.call(data);
        require(ok, "ForeignCaller");
    }
}
