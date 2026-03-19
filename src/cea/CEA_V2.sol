// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CEA} from "./CEA.sol";

/// @title  CEA_V2
/// @notice Testnet-only v2 implementation with a VERSION getter for migration verification.
contract CEA_V2 is CEA {
    /// @notice Returns the implementation version.
    function VERSION() external pure returns (string memory) {
        return "2";
    }
}
