//! Security-sensitive Common Foundry wallet primitives.
//!
//! Private key bytes are owned only by [`vault::WalletVault`]. Public callers
//! can create, restore, unlock, lock and sign, but cannot export a plaintext
//! key. The algorithms and byte layouts are ported from Common Foundry
//! v1.0.16 (`e5f0cda2be60b9f7ee8d7f13bbeb9856d2edcf17`).

#![forbid(unsafe_code)]

pub mod address;
pub mod amount;
pub mod backup;
pub mod network;
pub mod transaction;
pub mod vault;

pub use address::{AddressCodec, AddressError, AddressFormat};
pub use amount::{AmountError, format_atoms, parse_cmfd};
pub use backup::{EncryptedBackup, WalletBackupError, WalletBackupInfo};
pub use network::{MAINNET, Network};
pub use transaction::{
    OutPoint, PaymentPlan, PaymentPlanner, PendingRegistry, PendingState, SignedTransaction,
    SpendingLimit, TransactionError, Utxo,
};
pub use vault::{VaultError, VaultStatus, WalletVault};
