// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title StringUtils
 * @dev Utility library to safely convert a decimal string to a uint256.
 */
library StringUtils {
    /**
     * @notice Converts a strictly numeric decimal string to a uint256.
     * @dev Reverts if the string contains non-digit characters or overflows uint256.
     * @param s The string to convert, e.g., "12345".
     * @return result The resulting unsigned integer.
     */
    function stringToExactUInt256(string memory s) internal pure returns (uint256 result) {
        bytes memory b = bytes(s);
        uint256 len = b.length;

        require(len > 0, "Empty string cannot be converted.");

        for (uint256 i = 0; i < len; ++i) {
            uint8 c = uint8(b[i]);
            require(c >= 48 && c <= 57, "Non-digit character found."); // ASCII '0' to '9'

            // Multiply current result by 10 and add the new digit
            result = result * 10 + (c - 48);
        }
    }
}
