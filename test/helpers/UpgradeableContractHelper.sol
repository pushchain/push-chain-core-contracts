// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title UpgradeableContractHelper
 * @notice Helper functions for testing upgradeable contracts
 */
contract UpgradeableContractHelper is Test {
    /**
     * @dev Deploy an upgradeable contract using ERC1967Proxy
     * @param implementation The implementation contract
     * @param initData The initialization data to pass to the proxy
     * @return proxy The deployed proxy contract
     */
    function deployUpgradeableContract(address implementation, bytes memory initData) public returns (address) {
        // Deploy the proxy
        ERC1967Proxy proxy = new ERC1967Proxy(implementation, initData);
        return address(proxy);
    }
}
