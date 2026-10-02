// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {IAGWFactory} from "../../src/agentic-commerce-8183/interfaces/external/IAGWFactory.sol";
import {ISmartSession} from "../../src/agentic-commerce-8183/interfaces/external/ISmartSession.sol";

/// @notice Pins the mirrored AGW interfaces against the live Donut deployment.
/// @dev - Skips unless PUSH_CHAIN_TESTNET_RPC_URL is set (forge also reads it from `.env`); no default RPC.
///      - Forks `FORK_BLOCK` if set, else the latest block: the public Donut RPC is not archival,
///        so the PRD's pinned block (`23296566`) is unreachable there. The asserted facts are
///        permanent once true. The block used is logged.
///      - A wrong mirror ABI reverts or decodes garbage, so three passing calls pin it.
contract RulesBindingHookForkTest is Test {
    address internal constant FACTORY = 0x2578041963f692f8b51A137A1c7ddc0c84a8226A;
    address internal constant ENGINE = 0x046B2874Fc9F920ad53A317b3cf9d3d1974466f3;
    address internal constant SMOKE_WALLET = 0x1A02CC8Ed94a160D490D6851401F6F3879c69991;

    function test_fork_mirrorsMatchDeployedAGW() public {
        string memory url = vm.envOr("PUSH_CHAIN_TESTNET_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        uint256 blk = vm.envOr("FORK_BLOCK", uint256(0));
        if (blk == 0) vm.createSelectFork(url);
        else vm.createSelectFork(url, blk);
        emit log_named_uint("fork block", block.number);

        assertTrue(IAGWFactory(FACTORY).isWallet(SMOKE_WALLET), "smoke wallet is an AGW");
        assertFalse(IAGWFactory(FACTORY).isWallet(makeAddr("nobody")), "random address is not");
        assertFalse(
            ISmartSession(ENGINE).isPermissionEnabled(bytes32(uint256(1)), SMOKE_WALLET), "unknown id is not enabled"
        );
    }
}
