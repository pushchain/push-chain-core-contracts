// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UEAErrors} from "../libraries/Errors.sol";

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";

/**
 * @title   UEAProxy
 * @notice  Minimal proxy clone deployed by UEAFactory for each UEA.
 * @dev     Each UEAProxy delegates all calls to a UEA implementation contract.
 *          The implementation address is stored in UEA_LOGIC_SLOT.
 *          Deployed via CREATE2 using OpenZeppelin's Clones library.
 */
contract UEAProxy is Initializable, Proxy {
    // =========================
    //    UP: CONSTANTS
    // =========================

    /// @dev Storage slot for the current implementation address.
    ///      keccak256("uea.proxy.implementation") - 1
    bytes32 private constant UEA_LOGIC_SLOT =
        0x868a771a75a4aa6c2be13e9a9617cb8ea240ed84a3a90c8469537393ec3e115d;

    // =========================
    //    UP: INITIALIZER
    // =========================

    /// @notice              Initializes the proxy with a UEA implementation.
    /// @dev                 Can only be called once. Intended caller: UEAFactory.
    /// @param _logic        Address of the UEA implementation contract
    function initializeUEA(address _logic) external initializer {
        address currentImpl = getImplementation();
        if (currentImpl != address(0)) {
            revert UEAErrors.InvalidCall();
        }

        assembly {
            sstore(UEA_LOGIC_SLOT, _logic)
        }
    }

    // =========================
    //    UP_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the current UEA implementation address.
    /// @return impl        Implementation address stored in UEA_LOGIC_SLOT
    function getImplementation()
        public
        view
        returns (address impl)
    {
        assembly {
            impl := sload(UEA_LOGIC_SLOT)
        }
    }

    // =========================
    //    UP_2: INTERNAL HELPERS
    // =========================

    /// @dev Returns the implementation address for delegation.
    ///      Reverts if no implementation has been set.
    function _implementation()
        internal
        view
        virtual
        override
        returns (address)
    {
        address impl = getImplementation();
        if (impl == address(0)) {
            revert UEAErrors.InvalidCall();
        }
        return impl;
    }
}
