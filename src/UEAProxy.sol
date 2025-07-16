// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;


import {Errors} from "./libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @title UEAProxy
 * @dev This is the clone that gets deployed via EIP1167 by UEAFactory. 
 *      This represents a proxy contract that forwards all calls to a pre-defined UEA implementation contract.
 *      The Implementation contract is stored in the UEA_LOGIC_SLOT, i.e., keccak256("uea.proxy.implementation") - 1.
 *      The proxy is designed to be deployed via CREATE2 using OpenZeppelin's Clones library.
 *      Any calls to the proxy will be forwarded to the implementation contract.
 */
contract UEAProxy is Initializable {

    /// @dev Storage slot with the address of the current implementation.
    /// This is the keccak-256 hash of "uea.proxy.implementation" subtracted by 1
    bytes32 private constant UEA_LOGIC_SLOT = 0x5f15d873c0e739ae79493cec2a0d5a18f20f9d7e4d1ddb3be2ba05f35764097e;
    /**
     * @dev Initializes the proxy with an implementation address.
     * Can only be called once.
     * @param _logic The address of the UEA implementation contract
     */
    function initializeUEA(address _logic) external initializer {
        address currentImpl = getImplementation();
        if (currentImpl != address(0)) {
            revert Errors.InvalidCall();
        }

        assembly {
            sstore(UEA_LOGIC_SLOT, _logic)
        }
        
    }

    /**
     * @dev Returns the current implementation address.
     * @return impl The address of the current implementation
     */
    function getImplementation() public view returns (address impl) {
        assembly {
            impl := sload(UEA_LOGIC_SLOT)
        }
    }

    /**
     * @dev Delegates the current call to the implementation.
     */
    fallback() external payable {
        address implementation = getImplementation();

        if (implementation == address(0)) {    
            revert Errors.InvalidCall();
        }

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            returndatacopy(0, 0, returndatasize())
            if iszero(result) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}