// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMultiGuard {
    function hasGuard(address safe, address guard) external view returns (bool);
}
