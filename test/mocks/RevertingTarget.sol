// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title RevertingTarget
 * @notice Helper contract for testing revert behavior
 */
contract RevertingTarget {
    function revertWithReason() external pure {
        revert("This function always reverts with reason");
    }
}

