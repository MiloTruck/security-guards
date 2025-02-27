// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISafe {
    function nonce() external view returns (uint256);

    function isOwner(address owner) external view returns (bool);

    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
}
