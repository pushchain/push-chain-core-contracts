// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalReadClient} from "../../src/UniversalReadClient.sol";
import {ReadSpec} from "../../src/libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";

/// @dev Client that re-enters `withdraw()` from inside its own callback, and
///      records the balance it was credited before the callback ran.
contract ReentrantReadClient is UniversalReadClient {
    uint256 public lastRequestId;
    uint256 public creditSeenDuringCallback;
    bool public reentrySucceeded;

    constructor(
        address universalCallback_
    ) UniversalReadClient(universalCallback_) {}

    function requestSync(uint256 amount) external payable {
        ReadSpec memory spec = ReadSpec({
            account: UniversalAccountId({
                chainNamespace: "eip155",
                chainId: "1",
                owner: abi.encode(0x000000000000000000000000000000000000dEaD)
            }),
            query: abi.encode(amount),
            minConfirmations: 10,
            blockNumber: 100,
            expiryPushChainHeight: uint64(block.number + 1000),
            maxFee: 100 ether
        });

        lastRequestId = _requestRead(spec, "", 500000);
    }

    receive() external payable {}

    function reclaimRefunds() external returns (uint256) {
        return _withdrawRefunds();
    }

    function _onReadResult(
        uint256 requestId,
        bytes calldata resultData,
        bytes memory localState
    ) internal override {
        creditSeenDuringCallback = UNIVERSAL_CALLBACK.withdrawable(address(this));

        try UNIVERSAL_CALLBACK.withdraw() {
            reentrySucceeded = true;
        } catch {
            reentrySucceeded = false;
        }
    }
}
