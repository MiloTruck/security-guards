// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum, ISafe, Guard} from "./Guard.sol";

/// @notice Imposes security restrictions on transactions
/// @author MiloTruck
contract RestrictiveGuard is Guard {
    function beforeExecutionHook(SafeTransaction calldata safeTx, ISafe safe) external view override {
        // Disallow delegate calls
        require(safeTx.operation != Enum.Operation.DelegateCall, "Delegate call disallowed");

        // Disallow gas payments
        // Prevents transferring tokens through gas refunds
        // https://medium.com/@flackoon/your-safe-wallet-guard-might-not-be-enough-523f28924922
        require(safeTx.gasPrice == 0, "Gas refunds disallowed");

        // Only owners can execute transactions
        // Prevents manipulating admin functionality in protocols
        // H-1 in https://github.com/ethereum-optimism/optimism/blob/develop/docs/security-reviews/2023_12_SuperchainConfigUpgrade_Trust.pdf
        require(safe.isOwner(safeTx.msgSender), "Executor is not an owner");
    }
}
