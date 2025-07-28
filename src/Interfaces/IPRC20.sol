// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPRC20 is IERC20 {
    //Events
    event Minted(address indexed _to, uint256 indexed _value);
    event Withdraw(address indexed _from, bytes indexed _to, uint256 indexed _value);

    // PRC20 specific functions
    function mint(address to, uint256 amount) external;

    function burn(uint256 amount) external returns (bool);

    function withdraw(bytes memory _to, uint256 _amount) external;

    function getGasFee() external view returns (uint256);

    function setSyntheticModuleAddress(address newSyntheticModule) external;

    function setProtocolFlatFee(uint256 newFee) external;

    function setGasLimit(uint256 newGasLimit) external;
}
