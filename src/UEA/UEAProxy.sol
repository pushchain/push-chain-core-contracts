// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors as Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";

/**
 * @title UEAProxy
 * @dev This is the clone that gets deployed via EIP1167 by UEAFactory.
 *      This represents a proxy contract that forwards all calls to a pre-defined UEA implementation contract.
 *      The Implementation contract is stored in the UEA_LOGIC_SLOT, i.e., keccak256("uea.proxy.implementation") - 1.
 *      The proxy is designed to be deployed via CREATE2 using OpenZeppelin's Clones library.
 *      Any calls to the proxy will be forwarded to the implementation contract.
 */
contract UEAProxy is Initializable, Proxy {
    /// @dev Storage slot with the address of the current implementation.
    /// This is the keccak-256 hash of "uea.proxy.implementation" subtracted by 1
    bytes32 private constant UEA_LOGIC_SLOT = 0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;
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
     * @dev Returns the address to which the fallback function should delegate.
     * Reverts with Errors.InvalidCall() if no implementation has been set.
     * This function overrides OpenZeppelin's Proxy logic.
     */
    function _implementation() internal view virtual override returns (address) {
        address impl = getImplementation();
        if (impl == address(0)) {
            revert Errors.InvalidCall();
        }
        return impl;
    }
}
