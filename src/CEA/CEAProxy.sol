// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CEAErrors as Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";

/**
 * @title CEAProxy
 * @dev
 *  - This is the clone that gets deployed via EIP-1167 by CEAFactory.
 *  - Each CEAProxy delegates all calls to a CEA implementation contract.
 *  - The implementation address is stored in a dedicated storage slot (CEA_LOGIC_SLOT),
 *    similar to UEAProxy.
 *
 *  Flow:
 *   1. CEAFactory clones this proxy using Clones.cloneDeterministic.
 *   2. CEAFactory calls `initializeCEAProxy(ceaImplementation)` ONCE.
 *   3. CEAFactory then calls `CEA.initializeCEA(uea, vault, universalGateway)` THROUGH the proxy.
 *
 *  Notes:
 *   - There is NO upgrade mechanism here: once implementation is set, it cannot be changed.
 *   - All CEA state (UEA, VAULT, UNIVERSAL_GATEWAY, etc.) lives in the proxy’s storage via delegatecall.
 */
contract CEAProxy is Initializable, Proxy {
    /**
     * @dev Storage slot with the address of the current implementation.
     * This follows the EIP-1967 convention style:
     *   bytes32(uint256(keccak256("cea.proxy.implementation")) - 1)
     */
    bytes32 private constant CEA_LOGIC_SLOT = 0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    /**
     * @dev Initializes the proxy with a CEA implementation address.
     * Can only be called once per proxy instance.
     * @param _logic The address of the CEA implementation contract.
     *
     * Requirements:
     *  - `_logic` must be non-zero.
     *  - Proxy must not have an implementation already set.
     *
     * Intended caller:
     *  - CEAFactory, immediately after cloneDeterministic.
     */
    function initializeCEAProxy(address _logic) external initializer {
        if (_logic == address(0)) {
            revert Errors.InvalidCall(); // or InvalidInput, depending on your Errors design
        }

        address currentImpl = getImplementation();
        if (currentImpl != address(0)) {
            revert Errors.InvalidCall();
        }

        assembly {
            sstore(CEA_LOGIC_SLOT, _logic)
        }
    }

    /**
     * @notice Returns the current CEA implementation address stored in the proxy.
     * @dev Reads the implementation address from the CEA_LOGIC_SLOT storage slot.
     */
    function getImplementation() public view returns (address impl) {
        assembly {
            impl := sload(CEA_LOGIC_SLOT)
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