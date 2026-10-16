// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {E2E} from "./E2EConfig.sol";
import {UniversalAccountId} from "../../../src/libraries/Types.sol";

interface IE2EUEAFactory {
    function getUEAForOrigin(UniversalAccountId memory id) external view returns (address uea, bool isDeployed);
    function deployUEA(UniversalAccountId memory id) external returns (address);
}

interface IE2ECEAFactory {
    function computeCEA(address pushAccount) external view returns (address cea);
}

/// @title E2EAccounts — who the job is for (see README.md)
/// @notice push(), on Push Donut: the job's client. EOA mode: the client key's address. UEA mode
///         (`CLIENT_MODE=uea`): the client key's UEA, deployed by the relayer if it doesn't exist yet.
///         base(), on Base Sepolia: the account the reads measure. EOA mode: the client's address. UEA mode: the
///         UEA's CEA, from the CEA factory (readable before the CEA is deployed).
contract E2EAccounts is Script {
    function push() external {
        require(block.chainid == E2E.PUSH_DONUT_CHAIN_ID, "E2EAccounts.push: not Push Donut (42101)");
        address owner = E2E.client();
        E2E.Accounts memory a = E2E.Accounts({uea: E2E.ueaMode(), owner: owner, client: owner, measured: owner});
        if (a.uea) {
            UniversalAccountId memory origin = E2E.ueaOrigin();
            IE2EUEAFactory factory = IE2EUEAFactory(E2E.UEA_FACTORY);
            (address uea, bool deployed) = factory.getUEAForOrigin(origin);
            if (!deployed) {
                vm.startBroadcast(E2E.relayerKey());
                factory.deployUEA(origin);
                vm.stopBroadcast();
            }
            a.client = uea;
            a.measured = address(0); // base() resolves the CEA
            console.log("UEA origin:   eip155 /", origin.chainId);
            console.log(deployed ? "UEA (exists): " : "UEA (deployed):", uea);
        }
        E2E.saveAccounts(a);
        console.log("mode:         ", a.uea ? "uea" : "eoa");
        console.log("client key:   ", owner);
        console.log("job client:   ", a.client);
    }

    function base() external {
        require(block.chainid == E2E.BASE_SEPOLIA_CHAIN_ID, "E2EAccounts.base: not Base Sepolia (84532)");
        E2E.Accounts memory a = E2E.loadAccounts();
        a.measured = a.uea ? IE2ECEAFactory(E2E.CEA_FACTORY).computeCEA(a.client) : a.client;
        E2E.saveAccounts(a);
        console.log(a.uea ? "measured (the UEA's CEA):" : "measured (the client):", a.measured);
    }
}
