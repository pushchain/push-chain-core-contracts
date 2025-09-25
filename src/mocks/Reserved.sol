// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title Reserved
 * @notice The Reserved contract is for keeping a vanity address reserved
 */
contract Reserved is Initializable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializer function for the upgradeable contract.
     */
    function initialize() public virtual initializer {}
}
