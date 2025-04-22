// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title CAIP10
 * @dev Implementation of the Chain Agnostic Account ID standard (CAIP-10)
 * Format: blockchain_namespace:blockchain_reference:account_address
 */
library CAIP10 {
    struct ChainAccount {
        string namespace;      // e.g., "eip155" for EVM chains
        string chainid;      // e.g., "1" for Ethereum mainnet
        address accountAddress;
    }
    
    // Create a CAIP-10 identifier from components
    function createCAIP10(string memory namespace, string memory chainid, address accountAddress) 
        public pure returns (string memory) {
        return string(abi.encodePacked(
            namespace,
            ":",
            chainid,
            ":",
            addressToString(accountAddress)
        ));
    }

    function createSolanaCAIP10(string memory chainid, string memory accountAddress) 
        public pure returns (string memory) {
        return string(abi.encodePacked(
            "solana",
            ":",
            chainid,
            ":",
            accountAddress
        ));
    }
    
    // Helper: Convert address to string
    function addressToString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        
        return string(str);
    }
}