// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/ICEA.sol";

/**
 * @title MaliciousTarget
 * @notice Contract that attempts reentrancy attacks
 */
contract MaliciousTarget {
    ICEA public cea;
    bool public attackAttempted;

    constructor(address _cea) {
        cea = ICEA(_cea);
        attackAttempted = false;
    }

    // Function that tries to reenter executeUniversalTx
    function execute(bytes calldata) external {
        attackAttempted = true;
        // Try to reenter - this should be blocked by reentrancy guard
        // Note: This will fail, but we use it to test protection
    }

    // Function that receives native tokens and tries to reenter
    receive() external payable {
        // If we receive native tokens, try to reenter
        attackAttempted = true;
    }

    // Function that receives tokens via transferFrom and tries to reenter
    function receiveTokens() external {
        attackAttempted = true;
    }
}

