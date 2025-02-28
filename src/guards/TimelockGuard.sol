// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EnumerableSet} from "@openzeppelin/utils/structs/EnumerableSet.sol";
import {Enum, ISafe, Guard} from "./Guard.sol";
import {IMultiGuard} from "src/interfaces/IMultiGuard.sol";

/// @notice Imposes a timelock on all transactions
/// @dev WARNING: setDelay and setCancellor must be called after adding this guard
/// @author MiloTruck
contract TimelockGuard is Guard {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event DelayChanged(address indexed safe, uint256 delay);
    event CancellorChanged(address indexed safe, address cancellor);
    event TransactionScheduled(address indexed safe, bytes32 txHash);
    event TransactionExecuted(address indexed safe, bytes32 txHash);
    event TransactionCancelled(address indexed safe, bytes32 txHash);

    /// @dev Timelock parameters
    struct TimelockConfig {
        uint256 delay;
        address cancellor;
    }

    /// @dev Transaction data
    struct Transaction {
        SafeTransaction safeTx;
        uint256 timestamp;
    }

    /// @dev MultiGuard address
    IMultiGuard public immutable MULTI_GUARD;

    /// @dev Mapping of Safe address to timelock configuration
    mapping(address => TimelockConfig) public timelockConfig;

    /// @dev Mapping of Safe address to scheduled transaction hashes
    mapping(address => EnumerableSet.Bytes32Set) internal scheduledTxHashes;

    /// @dev Mapping to store transaction data
    mapping(address => mapping(bytes32 => Transaction)) public txData;

    constructor(address multiGuard) {
        MULTI_GUARD = IMultiGuard(multiGuard);
    }

    // ======================================== MODIFIERS ========================================

    modifier onlyInstalled(address safe) {
        require(MULTI_GUARD.hasGuard(safe, address(this)), "TimelockGuard not installed");
        _;
    }

    // ======================================== CONFIGURATION FUNCTIONS ========================================

    /// @notice Set timelock delay for a Safe address
    /// @dev Called by the Safe contract
    function setDelay(uint256 delay) external onlyInstalled(msg.sender) {
        timelockConfig[msg.sender].delay = delay;

        emit DelayChanged(msg.sender, delay);
    }

    /// @notice Set cancellor for a Safe address
    /// @dev Called by the Safe contract
    function setCancellor(address cancellor) external onlyInstalled(msg.sender) {
        timelockConfig[msg.sender].cancellor = cancellor;

        emit CancellorChanged(msg.sender, cancellor);
    }

    // ======================================== TIMELOCK FUNCTIONS ========================================

    /// @notice Schedule a transaction
    /// @dev Transactions can only be scheduled for execution by a Safe's owners
    function schedule(address safeAddress, SafeTransaction calldata safeTx) external onlyInstalled(safeAddress) {
        ISafe safe = ISafe(safeAddress);

        // Only owners can propose transactions
        require(safe.isOwner(msg.sender), "Not an owner");

        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            safeTx.nonce
        );

        // Store transaction
        require(scheduledTxHashes[safeAddress].add(txHash), "Transaction already scheduled");
        txData[safeAddress][txHash] =
            Transaction({safeTx: safeTx, timestamp: block.timestamp + timelockConfig[safeAddress].delay});

        emit TransactionScheduled(safeAddress, txHash);
    }

    /// @notice Cancel a scheduled transaction
    function cancel(address safeAddress, bytes32 txHash) external onlyInstalled(safeAddress) {
        require(msg.sender == timelockConfig[safeAddress].cancellor, "Not cancellor");

        // Remove transaction
        require(scheduledTxHashes[safeAddress].remove(txHash), "Transaction not scheduled");
        delete txData[safeAddress][txHash];

        emit TransactionCancelled(safeAddress, txHash);
    }

    // ======================================== GUARD FUNCTIONS ========================================

    function beforeExecutionHook(SafeTransaction calldata safeTx, bytes calldata, address, ISafe safe)
        external
        override
    {
        // Allow cancellor to be set without going through timelock
        // If a malicious cancellor rejects all transactions, owners can immediately change the cancellor
        if (
            safeTx.operation == Enum.Operation.Call && safeTx.to == address(this)
                && bytes4(safeTx.data[:4]) == this.setCancellor.selector
        ) {
            return;
        }

        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            safeTx.nonce
        );

        // Check timelock delay has passed
        uint256 timestamp = txData[address(safe)][txHash].timestamp;
        require(timestamp != 0 && block.timestamp > timestamp, "Timelock delay not passed");

        // Remove transaction from scheduled set
        require(scheduledTxHashes[address(safe)].remove(txHash), "Transaction not scheduled");

        emit TransactionExecuted(address(safe), txHash);
    }

    /// @dev WARNING: If too many transactions are scheduled, this function may run out of gas
    function onRemove(address safe) external override {
        // Clear timelock configuration
        delete timelockConfig[safe];

        // Remove all scheduled transactions
        while (scheduledTxHashes[safe].length() != 0) {
            bytes32 txHash = scheduledTxHashes[safe].at(0);

            delete txData[safe][txHash];
            scheduledTxHashes[safe].remove(txHash);
        }
    }

    // ======================================== VIEW FUNCTIONS ========================================

    /// @notice Get all scheduled transactions for a Safe address
    function getTransactions(address safe)
        external
        view
        returns (bytes32[] memory txHashes, Transaction[] memory transactions)
    {
        txHashes = scheduledTxHashes[safe].values();
        transactions = new Transaction[](txHashes.length);
        for (uint256 i; i < txHashes.length; i++) {
            transactions[i] = txData[safe][txHashes[i]];
        }
    }
}
