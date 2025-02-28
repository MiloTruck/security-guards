// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Enum, BaseGuard} from "@safe/base/GuardManager.sol";
import {EnumerableSet} from "@openzeppelin/utils/structs/EnumerableSet.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {Guard} from "./guards/Guard.sol";

/// @notice Forwards pre and post transaction hooks to multiple guards
/// @dev This contract should be set as the guard address in a Safe account
/// @dev Compatible with Safe v1.4.1
/// @author MiloTruck
contract MultiGuard is BaseGuard {
    using EnumerableSet for EnumerableSet.AddressSet;

    event GuardAdded(address indexed safe, address indexed guard);
    event GuardRemoved(address indexed safe, address indexed guard);

    /// @dev Storage slot of the guard address in a Safe account
    /// From https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/base/GuardManager.sol#L41-L42
    uint256 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @dev Mapping of Safe address to installed guards
    mapping(address => EnumerableSet.AddressSet) internal guards;

    // ======================================== CONFIGURATION FUNCTIONS ========================================

    /// @notice Add a guard to a Safe address
    /// @dev Called by the Safe contract
    /// @dev WARNING: If too many guards are added, both hooks may run out of gas and revert
    function addGuard(address guard) external {
        require(isInstalled(msg.sender), "MultiGuard not installed");

        require(guards[msg.sender].add(guard), "Guard already added");

        emit GuardAdded(msg.sender, guard);
    }

    /// @notice Remove a guard from a Safe address
    /// @dev Called by the Safe contract
    function removeGuard(address guard) external {
        require(isInstalled(msg.sender), "MultiGuard not installed");

        require(guards[msg.sender].remove(guard), "Guard not added");

        Guard(guard).onRemove(msg.sender);

        emit GuardRemoved(msg.sender, guard);
    }

    // ======================================== GUARD FUNCTIONS ========================================

    /// @notice Pre-transaction hook called by the Safe contract
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address msgSender
    ) external {
        // Include current nonce in transaction
        Guard.SafeTransaction memory safeTx = Guard.SafeTransaction({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: safeTxGas,
            baseGas: baseGas,
            gasPrice: gasPrice,
            gasToken: gasToken,
            refundReceiver: refundReceiver,
            nonce: ISafe(msg.sender).nonce() - 1
        });

        // Call pre-transaction hook for all guards
        address[] memory _guards = getGuards(msg.sender);
        for (uint256 i; i < _guards.length; i++) {
            Guard(_guards[i]).beforeExecutionHook(safeTx, signatures, msgSender, ISafe(msg.sender));
        }
    }

    /// @notice Post-transaction hook called by the Safe contract
    function checkAfterExecution(bytes32 txHash, bool success) external {
        // Ensure all guards were removed before uninstallation
        if (!isInstalled(msg.sender)) {
            require(guards[msg.sender].length() == 0, "Guards not removed");
        }

        // Call post-transaction hook for all guards
        address[] memory _guards = getGuards(msg.sender);
        for (uint256 i; i < _guards.length; i++) {
            Guard(_guards[i]).afterExecutionHook(txHash, success, ISafe(msg.sender));
        }
    }

    // ======================================== VIEW FUNCTIONS ========================================

    /// @notice Get all guards for a Safe address
    function getGuards(address safe) public view returns (address[] memory) {
        return guards[safe].values();
    }

    /// @notice Check if this contract is set as the guard address in a Safe account
    function isInstalled(address safe) public view returns (bool) {
        bytes memory data = ISafe(safe).getStorageAt(GUARD_STORAGE_SLOT, 1);
        address guard = abi.decode(data, (address));

        return guard == address(this);
    }

    /// @notice Check if a guard is added to a Safe address
    function hasGuard(address safe, address guard) external view returns (bool) {
        return guards[safe].contains(guard);
    }
}
