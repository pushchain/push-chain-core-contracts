// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

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

        require(len > 0, "Empty string cannot be converted.");

        for (uint256 i = 0; i < len; ++i) {
            uint8 c = uint8(b[i]);
            require(c >= 48 && c <= 57, "Non-digit character found.");

            result = result * 10 + (c - 48);
        }
    }
}
