// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum} from "@safe/common/Enum.sol";
import {ISafe} from "src/interfaces/ISafe.sol";

/// @notice Base guard meant to be inherited by custom guards
/// @author MiloTruck
abstract contract Guard {
    struct SafeTransaction {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }

    function beforeExecutionHook(
        SafeTransaction calldata safeTransaction,
        bytes calldata signatures,
        address msgSender,
        ISafe safe
    ) external virtual {}

    function afterExecutionHook(bytes32 txHash, bool success, ISafe safe) external virtual {}

    function onRemove(address safe) external virtual {}
}
