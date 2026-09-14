// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {UniversalReadClient} from "./UniversalReadClient.sol";
import {ReadSpec} from "./libraries/ReadTypes.sol";

contract UniversalReadRegistry is UniversalReadClient {
    struct StoredResult {
        uint256 requestId;
        bytes resultData;
        uint64 updatedAtBlock;
    }

    uint256 private _readNonce;

    mapping(uint256 => address) public readerOf;
    mapping(uint256 => bytes32) public queryKeyOf;
    mapping(uint256 => uint256) public requestOrderOf;
    mapping(uint256 => StoredResult) private _resultByRequestId;
    mapping(address => mapping(bytes32 => uint256)) private _latestRequestId;
    mapping(address => mapping(bytes32 => uint256)) private _latestOrder;

    event RegistryReadRequested(uint256 indexed requestId, address indexed reader, bytes32 indexed queryKey);
    event RegistryReadStored(uint256 indexed requestId, address indexed reader, bytes32 indexed queryKey);

    constructor(address universalCallback_) UniversalReadClient(universalCallback_) {}

    function read(ReadSpec calldata spec, uint64 callbackGasLimit)
        external
        payable
        returns (uint256 requestId)
    {
        ReadSpec memory s = spec;
        s.revertRecipient = msg.sender;

        bytes32 qk = keccak256(abi.encode(spec.account, spec.query));
        uint256 order = ++_readNonce;

        requestId = _requestRead(s, abi.encode(msg.sender, qk, order), callbackGasLimit);

        readerOf[requestId] = msg.sender;
        queryKeyOf[requestId] = qk;
        requestOrderOf[requestId] = order;

        emit RegistryReadRequested(requestId, msg.sender, qk);
    }

    function _onReadResult(uint256 requestId, bytes calldata resultData, bytes memory localState)
        internal
        override
    {
        (address reader, bytes32 qk, uint256 order) = abi.decode(localState, (address, bytes32, uint256));

        _resultByRequestId[requestId] =
            StoredResult({requestId: requestId, resultData: resultData, updatedAtBlock: uint64(block.number)});

        if (order > _latestOrder[reader][qk]) {
            _latestOrder[reader][qk] = order;
            _latestRequestId[reader][qk] = requestId;
        }

        emit RegistryReadStored(requestId, reader, qk);
    }

    function resultByRequestId(uint256 requestId) external view returns (StoredResult memory) {
        return _resultByRequestId[requestId];
    }

    function latestResult(address reader, bytes32 queryKey) external view returns (StoredResult memory) {
        return _resultByRequestId[_latestRequestId[reader][queryKey]];
    }

    function hasResult(uint256 requestId) external view returns (bool) {
        return _resultByRequestId[requestId].updatedAtBlock != 0;
    }
}
