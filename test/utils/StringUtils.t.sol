// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../src/libraries/Utils.sol";

/**
 * @title StringUtilsTest
 * @dev Test suite for the StringUtils library
 */
contract StringUtilsTest is Test {
    // Helper function to expose the internal function for testing
    function stringToUint(string memory s) public pure returns (uint256) {
        return StringUtils.stringToExactUInt256(s);
    }

    function testConvertValidSingleDigit() public pure {
        assertEq(stringToUint("0"), 0, "Failed to convert '0'");
        assertEq(stringToUint("5"), 5, "Failed to convert '5'");
        assertEq(stringToUint("9"), 9, "Failed to convert '9'");
    }

    function testConvertValidMultiDigit() public pure {
        assertEq(stringToUint("10"), 10, "Failed to convert '10'");
        assertEq(stringToUint("123"), 123, "Failed to convert '123'");
        assertEq(stringToUint("9876"), 9876, "Failed to convert '9876'");
        assertEq(stringToUint("10000"), 10000, "Failed to convert '10000'");
    }

    function testConvertLargeNumber() public pure {
        assertEq(stringToUint("123456789"), 123456789, "Failed to convert '123456789'");
        assertEq(stringToUint("1000000000"), 1000000000, "Failed to convert '1000000000'");
        assertEq(stringToUint("2147483647"), 2147483647, "Failed to convert '2147483647' (2^31-1)");
    }

    function testConvertVeryLargeNumber() public pure {
        assertEq(
            stringToUint("115792089237316195423570985008687907853269984665640564039457584007913129639935"), 
            115792089237316195423570985008687907853269984665640564039457584007913129639935, 
            "Failed to convert max uint256 value"
        );
    }

    function testConvertWithLeadingZeros() public pure {
        assertEq(stringToUint("000"), 0, "Failed to convert '000'");
        assertEq(stringToUint("001"), 1, "Failed to convert '001'");
        assertEq(stringToUint("0123"), 123, "Failed to convert '0123'");
        assertEq(stringToUint("000456"), 456, "Failed to convert '000456'");
    }

    function testRevertOnEmptyString() public {
        // Test that calling with an empty string reverts
        bool success = false;
        try this.stringToUint("") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "Empty string should revert");
    }

    function testRevertOnNonDigitCharacters() public {
        // Test that calling with non-digit characters reverts
        bool success = false;
        
        // Test "123a"
        try this.stringToUint("123a") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with letters should revert");
        
        // Test "a123"
        success = false;
        try this.stringToUint("a123") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with letters should revert");
        
        // Test "12.34"
        success = false;
        try this.stringToUint("12.34") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with decimal point should revert");
    }

    function testRevertOnSpecialCharacters() public {
        // Test that calling with special characters reverts
        bool success = false;
        
        // Test "123$"
        try this.stringToUint("123$") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with special characters should revert");
        
        // Test "#123"
        success = false;
        try this.stringToUint("#123") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with special characters should revert");
        
        // Test "1,234"
        success = false;
        try this.stringToUint("1,234") {
            success = true;
        } catch {
            // This is expected to fail
        }
        assertFalse(success, "String with commas should revert");
    }

    function testFuzzValidDigits(uint8 digit) public pure {
        // Ensure digit is between 0-9
        vm.assume(digit <= 9);
        
        // Convert digit to string
        string memory digitStr = vm.toString(digit);
        
        // Test conversion
        assertEq(stringToUint(digitStr), digit, "Failed to convert fuzzed digit");
    }

    function testFuzzValidNumbers(uint256 number) public pure {
        // Convert number to string
        string memory numberStr = vm.toString(number);
        
        // Test conversion
        assertEq(stringToUint(numberStr), number, "Failed to convert fuzzed number");
    }
} 