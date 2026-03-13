// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CEAErrors} from "../libraries/Errors.sol";

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";

/**
 * @title   CEAProxy
 * @notice  Minimal proxy clone deployed by CEAFactory for each CEA.
 * @dev     Each CEAProxy delegates all calls to a CEA implementation contract.
 *          The implementation address is stored in a dedicated storage slot
 *          (CEA_LOGIC_SLOT), similar to UEAProxy.
 *
 *          Flow:
 *          1. CEAFactory clones this proxy via Clones.cloneDeterministic.
 *          2. CEAFactory calls initializeCEAProxy(ceaImplementation) ONCE.
 *          3. CEAFactory calls CEA.initializeCEA(...) THROUGH the proxy.
 *
 *          Implementation can be upgraded via migration flow
 *          (CEA -> CEAMigration delegatecall).
 */
contract CEAProxy is Initializable, Proxy {
    // =========================
    //    CP: CONSTANTS
    // =========================

    /// @dev Storage slot for the current implementation address.
    ///      bytes32(uint256(keccak256("cea.proxy.implementation")) - 1)
    bytes32 private constant CEA_LOGIC_SLOT =
        0x8b2ae8ee8c8678fc65d38e03fd33865426627999aa5e8fab985583dec5888813;

    // =========================
    //    CP: INITIALIZER
    // =========================

    /// @notice                  Initializes the proxy with a CEA implementation.
    /// @dev                     Can only be called once. Intended caller: CEAFactory.
    /// @param _logic            Address of the CEA implementation contract
    function initializeCEAProxy(address _logic) external initializer {
        if (_logic == address(0)) {
            revert CEAErrors.InvalidCall();
        }

        address currentImpl = getImplementation();
        if (currentImpl != address(0)) {
            revert CEAErrors.InvalidCall();
        }

        assembly {
            sstore(CEA_LOGIC_SLOT, _logic)
        }
    }

    // =========================
    //    CP_1: VIEW FUNCTIONS
    // =========================

    /// @notice             Returns the current CEA implementation address.
    /// @return impl        Implementation address stored in CEA_LOGIC_SLOT
    function getImplementation() public view returns (address impl) {
        assembly {
            impl := sload(CEA_LOGIC_SLOT)
        }
    }

    // =========================
    //    CP_2: INTERNAL HELPERS
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
            revert CEAErrors.InvalidCall();
        }
        return impl;
    }
}
