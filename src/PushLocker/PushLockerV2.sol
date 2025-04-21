// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PushLocker} from "./PushLocker.sol";
import {ISwapRouter, IWETH, AggregatorV3Interface} from "../Interfaces/AMMInterfaces.sol";

/// @custom:oz-upgrades-from PushLocker

//ONLY FOR TESTING PURPOSES
contract PushLockerV2 is PushLocker {
    //Mock function to recover tokens for V2
    string public constant name = "PushLockerV2";

    function initialize() external initializer {
        __ReentrancyGuard_init();
    }
}
