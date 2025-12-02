// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../../src/interfaces/IUniversalGateway.sol";

/**
 * @dev Mock Universal Gateway contract for testing
 */
contract MockUniversalGateway is IUniversalGateway {
    function sendUniversalTx(UniversalTxRequest calldata req) external payable {
        // Mock implementation - just accept the call
        // In tests, we can track calls via vm.expectCall if needed
    }
}

