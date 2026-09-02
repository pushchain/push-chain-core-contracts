// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalReadClient} from "../../src/UniversalReadClient.sol";
import {ReadSpec} from "../../src/libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";

contract RevertingReadClient is UniversalReadClient {
    error IntentionalRevert();
    uint256 public lastRequestId;

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
            maxFee: 100 ether,
            revertRecipient: address(this)
        });

        lastRequestId = _requestRead(spec, "", 200000);
    }

    receive() external payable {}

    function _onReadResult(
        uint256 requestId,
        bytes calldata resultData,
        bytes memory localState
    ) internal override {
        revert IntentionalRevert();
    }
}
