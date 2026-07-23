// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {CEAFactory} from "../../src/cea/CEAFactory.sol";

/**
 * @title VerifyOldCEAsScript
 * @notice Takes a push account address, looks up its CEA on the
 *         old factory, then reverse-looks up the CEA back to push
 *         account and confirms the round-trip matches.
 *
 * USAGE:
 *   forge script scripts/cea/verifyOldCEAs.s.sol:VerifyOldCEAsScript \
 *     --rpc-url "$ARB_TESTNET_RPC_URL" \
 *     --sig "run(address)" <PUSH_ACCOUNT> -vvvv
 */
contract VerifyOldCEAsScript is Script {
    address public OLD_CEA_FACTORY = 0x8ED594A83301FEc545fC6c19fc12cF7111777029;

    function run(address pushAccount) external view {
        CEAFactory factory = CEAFactory(OLD_CEA_FACTORY);

        address cea = factory.pushAccountToCEA(pushAccount);

        console.log("Push Account:", pushAccount);
        console.log("CEA:         ", cea);

        if (cea == address(0)) {
            console.log("RESULT: NO CEA found for this push account");
            return;
        }

        address reversePA = factory.ceaToPushAccount(cea);
        console.log("Reverse PA:  ", reversePA);

        if (reversePA == pushAccount) {
            console.log("RESULT: MATCH - round-trip verified");
        } else {
            console.log("RESULT: MISMATCH - reverse lookup returned different address");
        }
    }
}
