// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;


/**
 * @dev Minimal interface for the CEA proxy expected by CEAFactory.
 *
 *  This now reflects the actual CEAProxy contract:
 *    - Proxy is initialized once with the CEA logic implementation.
 */
interface ICEAProxy {
    /**
     * @notice Initializes the proxy with the CEA implementation.
     * @dev    MUST be callable only once per proxy instance.
     *
     * @param implementation Address of the CEA logic contract.
     */
    function initializeCEAProxy(address implementation) external;
}