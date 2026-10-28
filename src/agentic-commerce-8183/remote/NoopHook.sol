// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC8183Hook} from "../interfaces/IERC8183Hook.sol";

/// @title NoopHook — a hook that does nothing
/// @notice For kernels that refuse a job without a hook (APEX's `createJob` reverts `HookRequired` for `address(0)`).
///         The EvaluationGateway accepts only `address(0)` or this hook: any other hook runs inside `complete` and
///         could block payment, while `claimRefund` calls no hook.
/// @dev Answers ERC-165 for `IERC8183Hook`, which has the same interface id as the `IACPHook` both deployed kernels
///      check. Holds no state and ignores its caller, so anyone calling it changes nothing.
contract NoopHook is IERC8183Hook {
    function beforeAction(uint256, bytes4, bytes calldata) external pure {}

    function afterAction(uint256, bytes4, bytes calldata) external pure {}

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC8183Hook).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
