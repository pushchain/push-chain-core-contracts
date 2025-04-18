// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PushLocker} from "./PushLocker.sol";

/// @custom:oz-upgrades-from PushLocker

contract PushLockerV2 is PushLocker {
    //Mock function to recover tokens for V2
    string public constant name = "PushLockerV2";
}
