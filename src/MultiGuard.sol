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
    event GuardRemovalInitiated(address indexed safe, address indexed guard);
    event GuardRemoved(address indexed safe, address indexed guard);
    event UninstallInitiated(address indexed safe);

    /// @dev Storage slot of the guard address in a Safe account
    /// From https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/base/GuardManager.sol#L41-L42
    uint256 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @dev Delay for removing a guard or complete uninstallation
    /// Prevents instantly removing guards or uninstalling to bypass restrictions in subsequent transactions
    uint256 public constant DELAY = 3 days;

    /// @dev Mapping of Safe address to installed guards
    mapping(address => EnumerableSet.AddressSet) internal guards;

    /// @dev Mapping of pending removals for guards
    mapping(address => mapping(address => uint256)) public removeTimestamp;

    /// @dev Mapping of pending uninstalls
    mapping(address => uint256) public uninstallTimestamp;

    // ======================================== CONFIGURATION FUNCTIONS ========================================

    modifier onlyInstalled() {
        require(isInstalled(msg.sender), "MultiGuard not installed");
        _;
    }

    // ======================================== CONFIGURATION FUNCTIONS ========================================

    /// @notice Add a guard to a Safe address
    /// @dev Called by the Safe contract
    /// @dev WARNING: If too many guards are added, both hooks may run out of gas and revert
    function addGuard(address guard) external onlyInstalled {
        require(guards[msg.sender].add(guard), "Guard already added");

        emit GuardAdded(msg.sender, guard);
    }

    /// @notice Initiate a guard removal
    /// @dev Called by the Safe contract
    function initiateRemoveGuard(address guard) external onlyInstalled {
        require(guards[msg.sender].contains(guard), "Guard not added");

        removeTimestamp[msg.sender][guard] = block.timestamp + DELAY;

        emit GuardRemovalInitiated(msg.sender, guard);
    }

    /// @notice Remove a guard from a Safe address
    /// @dev Called by the Safe contract
    function removeGuard(address guard) external onlyInstalled {
        uint256 timestamp = removeTimestamp[msg.sender][guard];
        require(timestamp != 0 && block.timestamp > timestamp, "Delay not passed");

        guards[msg.sender].remove(guard);
        removeTimestamp[msg.sender][guard] = 0;

        emit GuardRemoved(msg.sender, guard);
    }

    /// @notice Initiate uninstallation of the MultiGuard contract
    /// @dev Called by a Safe account when changing its guard address
    /// @dev WARNING: Guards are not removed on uninstall. If a Safe account uninstalls MultiGuard and
    /// "reinstalls" it subsequently, all previous guards and removal timestamps will carry over
    function initiateUninstall() external onlyInstalled {
        uninstallTimestamp[msg.sender] = block.timestamp + DELAY;

        emit UninstallInitiated(msg.sender);
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
        // Caller is the Safe contract
        ISafe safe = ISafe(msg.sender);

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
            signatures: signatures,
            msgSender: msgSender,
            nonce: safe.nonce() - 1
        });

        // Call pre-transaction hook for all guards
        address[] memory _guards = getGuards(address(safe));
        for (uint256 i; i < _guards.length; i++) {
            Guard(_guards[i]).beforeExecutionHook(safeTx, safe);
        }
    }

    /// @notice Post-transaction hook called by the Safe contract
    function checkAfterExecution(bytes32 txHash, bool success) external {
        // Caller is the Safe contract
        ISafe safe = ISafe(msg.sender);

        // Ensure this contract was not uninstalled without a delay
        if (!isInstalled(address(safe))) {
            uint256 timestamp = uninstallTimestamp[msg.sender];
            require(timestamp != 0 && block.timestamp > timestamp, "Delay not passed");

            uninstallTimestamp[msg.sender] = 0;
        }

        // Call post-transaction hook for all guards
        address[] memory _guards = getGuards(address(safe));
        for (uint256 i; i < _guards.length; i++) {
            Guard(_guards[i]).afterExecutionHook(txHash, success, safe);
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
}
