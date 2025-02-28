// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum} from "@safe/common/Enum.sol";

interface ISafe {
    function nonce() external view returns (uint256);

    function isOwner(address owner) external view returns (bool);

    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
}
