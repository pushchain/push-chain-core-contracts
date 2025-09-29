// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title TestProxy
 * @dev Test proxy for delegatecall testing in UEA migration tests
 *      This contract simulates a UEA proxy for testing migration mechanics
 */
contract TestProxy {
    // Storage slot for implementation (matches UEA_LOGIC_SLOT)
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;
    
    /**
     * @dev Set the implementation address in storage
     * @param impl The implementation address to store
     */
    function setImplementation(address impl) external {
        assembly {
            sstore(UEA_LOGIC_SLOT, impl)
        }
    }
    
    /**
     * @dev Get the current implementation address from storage
     * @return impl The current implementation address
     */
    function getImplementation() external view returns (address impl) {
        assembly {
            impl := sload(UEA_LOGIC_SLOT)
        }
    }
    
    /**
     * @dev Perform a delegatecall to the target contract
     * @param target The target contract to delegatecall
     * @param data The calldata to send
     * @return success Whether the delegatecall succeeded
     * @return returnData The return data from the delegatecall
     */
    function delegateTo(address target, bytes calldata data) external returns (bool success, bytes memory returnData) {
        return target.delegatecall(data);
    }
    
    /**
     * @dev Get the storage value at a specific slot (for testing)
     * @param slot The storage slot to read
     * @return value The value stored at the slot
     */
    function getStorageAt(bytes32 slot) external view returns (bytes32 value) {
        assembly {
            value := sload(slot)
        }
    }
}
