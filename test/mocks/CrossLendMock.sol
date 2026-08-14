// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalReadClient} from "../../src/UniversalReadClient.sol";
import {ReadSpec} from "../../src/libraries/ReadTypes.sol";
import {UniversalAccountId} from "../../src/libraries/Types.sol";

contract CrossLendMock is UniversalReadClient {
    uint256 public lastRequestId;
    bytes public lastResultData;
    bytes public lastLocalState;

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

        bytes memory localState = abi.encode(amount, msg.sender);

        uint256 requestId = _requestRead(spec, localState, 200000);
        lastRequestId = requestId;
    }

    receive() external payable {}


    function _onReadResult(
        uint256 requestId,
        bytes calldata resultData,
        bytes memory localState
    ) internal override {
        lastRequestId = requestId;
        lastResultData = resultData;
        lastLocalState = localState;
    }
}
