// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {StringUtilsErrors} from "./Errors.sol";

/// @title  StringUtils
/// @notice Utility library for string-to-number conversion.
library StringUtils {
    /// @notice             Converts a strictly numeric decimal string to a uint256.
    /// @dev                Reverts if the string is empty, contains non-digit characters,
    ///                     or would overflow uint256.
    /// @param s            Decimal string to convert (e.g., "12345")
    /// @return result      The resulting unsigned integer
    function stringToExactUInt256(
        string memory s
    ) internal pure returns (uint256 result) {
        bytes memory b = bytes(s);
        uint256 len = b.length;

        if (len == 0) revert StringUtilsErrors.EmptyString();

        for (uint256 i = 0; i < len; ++i) {
            uint8 c = uint8(b[i]);
            if (c < 48 || c > 57) revert StringUtilsErrors.NonDigitCharacter();

            result = result * 10 + (c - 48);
        }
    }
}
