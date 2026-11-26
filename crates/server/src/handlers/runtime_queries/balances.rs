// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Balances and System pallet storage query functions.
//!
//! This module provides standalone functions for querying balance-related storage items
//! including System::Account, Balances::Locks, Proxy::Proxies, and Vesting::Vesting.

use parity_scale_codec::Decode;
use scale_value::{At, Composite, Value, ValueDef};
use sp_core::crypto::AccountId32;
use subxt::{OnlineClientAtBlock, SubstrateConfig};

// ================================================================================================
// SCALE Decode Types
// ================================================================================================

/// Account data for modern runtimes (with frozen field)
#[derive(Debug, Clone, Decode)]
#[allow(dead_code)]
struct AccountDataModern {
    free: u128,
    reserved: u128,
    frozen: u128,
    flags: u128,
}

/// Account data for legacy runtimes (with misc_frozen/fee_frozen fields)
#[derive(Debug, Clone, Decode)]
struct AccountDataLegacy {
    free: u128,
    reserved: u128,
    misc_frozen: u128,
    fee_frozen: u128,
}

/// Account info structure (modern runtime)
#[derive(Debug, Clone, Decode)]
#[allow(dead_code)]
struct AccountInfoModern {
    nonce: u32,
    consumers: u32,
    providers: u32,
    sufficients: u32,
    data: AccountDataModern,
}

/// Account info structure (legacy runtime)
#[derive(Debug, Clone, Decode)]
#[allow(dead_code)]
struct AccountInfoLegacy {
    nonce: u32,
    consumers: u32,
    providers: u32,
    sufficients: u32,
    data: AccountDataLegacy,
}

/// Account info structure for pre-sufficients era (before runtime v29).
/// Layout: nonce(4) + consumers(4) + providers(4) + AccountDataLegacy(64) = 76 bytes.
#[derive(Debug, Clone, Decode)]
#[allow(dead_code)]
struct AccountInfoPreSufficients {
    nonce: u32,
    consumers: u32,
    providers: u32,
    data: AccountDataLegacy,
}

/// Account info structure for earliest runtimes (single refcount field).
/// Layout: nonce(4) + refcount(u8) + AccountDataLegacy(64) = 69 bytes.
#[derive(Debug, Clone, Decode)]
#[allow(dead_code)]
struct AccountInfoRefcount {
    nonce: u32,
    refcount: u8,
    data: AccountDataLegacy,
}

/// Balance lock structure
#[derive(Debug, Clone, Decode, scale_decode::DecodeAsType)]
struct BalanceLock {
    id: [u8; 8],
    amount: u128,
    reasons: Reasons,
}

/// Lock reasons enum
#[derive(Debug, Clone, Decode, scale_decode::DecodeAsType)]
enum Reasons {
    Fee,
    Misc,
    All,
}

impl Reasons {
    fn as_str(&self) -> &'static str {
        match self {
            Reasons::Fee => "Fee",
            Reasons::Misc => "Misc",
            Reasons::All => "All",
        }
    }
}

/// Proxy definition structure
#[derive(Debug, Clone, Decode)]
struct ProxyDefinition {
    delegate: [u8; 32],
    proxy_type: u8,
    delay: u32,
}

/// Proxy storage value read with the chain metadata: any deposit width, and the proxy type as the
/// runtime names it.
#[derive(scale_decode::DecodeAsType)]
struct ProxyDefinitionNamed {
    delegate: [u8; 32],
    proxy_type: Value,
    delay: u32,
}

/// Vesting info structure
#[derive(Debug, Clone, Decode)]
struct VestingInfo {
    locked: u128,
    per_block: u128,
    starting_block: u32,
}

// ================================================================================================
// Public Data Types
// ================================================================================================

/// Decoded account data
#[derive(Debug, Clone)]
pub struct DecodedAccountData {
    pub nonce: u32,
    pub free: u128,
    pub reserved: u128,
    pub misc_frozen: Option<u128>,
    pub fee_frozen: Option<u128>,
    pub frozen: Option<u128>,
}

/// Decoded balance lock
#[derive(Debug, Clone)]
pub struct DecodedBalanceLock {
    pub id: String,
    pub amount: u128,
    pub reasons: String,
}

/// Decoded proxy definition
#[derive(Debug, Clone)]
pub struct DecodedProxyDefinition {
    pub delegate: String,
    pub proxy_type: String,
    pub delay: u32,
}

/// Decoded vesting info
#[derive(Debug, Clone)]
pub struct DecodedVestingInfo {
    pub locked: u128,
    pub per_block: u128,
    pub starting_block: u32,
}

// ================================================================================================
// Storage Query Functions
// ================================================================================================

/// Error reading an account's `System::Account` entry.
#[derive(Debug, thiserror::Error)]
pub enum AccountDataError {
    /// The storage fetch failed (transient / retryable).
    #[error(transparent)]
    Fetch(#[from] subxt::error::StorageError),

    /// Bytes were fetched but matched no known `AccountInfo` layout.
    #[error("failed to decode AccountInfo storage value ({0} bytes)")]
    Decode(usize),
}

/// Fetch the raw SCALE bytes of an account-keyed map storage entry.
///
/// `Ok(Some(bytes))` if present, `Ok(None)` if genuinely absent, `Err` if the fetch failed.
async fn try_fetch_storage(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    pallet: &str,
    entry: &str,
    account: &AccountId32,
) -> Result<Option<Vec<u8>>, subxt::error::StorageError> {
    let storage_addr = subxt::dynamic::storage::<_, ()>(pallet, entry);
    let account_bytes: [u8; 32] = *account.as_ref();

    Ok(client_at_block
        .storage()
        .try_fetch(storage_addr, (account_bytes,))
        .await?
        .map(|value| value.into_bytes()))
}

/// Read and decode an account's `System::Account` entry.
///
/// `Ok(Some)` if present and decoded, `Ok(None)` if genuinely absent, `Err(Fetch)` on a fetch
/// failure, `Err(Decode)` if the bytes could be decoded neither with the chain metadata nor as a
/// known fixed layout.
pub async fn get_account_data(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    account: &AccountId32,
) -> Result<Option<DecodedAccountData>, AccountDataError> {
    let storage_addr = subxt::dynamic::storage::<_, ()>("System", "Account");
    let account_bytes: [u8; 32] = *account.as_ref();

    let Some(value) = client_at_block
        .storage()
        .try_fetch(storage_addr, (account_bytes,))
        .await?
    else {
        return Ok(None);
    };

    // Metadata first: the byte length alone cannot tell `frozen`/`flags` from
    // `misc_frozen`/`fee_frozen` (both 80 bytes), nor a u128 `Balance` from another balance type
    // (u64 on Bittensor).
    if let Some(data) = value
        .decode_as::<Value>()
        .ok()
        .as_ref()
        .and_then(account_data_from_value)
    {
        return Ok(Some(data));
    }

    // Fixed layouts, for blocks whose metadata does not describe `AccountInfo` by these names.
    if let Some(data) = decode_account_info(value.bytes()) {
        return Ok(Some(data));
    }

    // Bytes present but undecodable is an error, not an absent account.
    warn_undecodable("AccountInfo", value.bytes());
    Err(AccountDataError::Decode(value.bytes().len()))
}

/// Like [`get_account_data`], but returns zeroed balances for a genuinely-absent account.
/// Fetch and decode errors still propagate — never a fabricated `free: 0`.
pub async fn get_account_data_or_default(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    account: &AccountId32,
) -> Result<DecodedAccountData, AccountDataError> {
    Ok(get_account_data(client_at_block, account)
        .await?
        .unwrap_or(DecodedAccountData {
            nonce: 0,
            free: 0,
            reserved: 0,
            misc_frozen: None,
            fee_frozen: None,
            frozen: Some(0),
        }))
}

/// Get balance locks from `Balances::Locks` (empty when absent; `Err` on fetch failure).
pub async fn get_balance_locks(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    account: &AccountId32,
) -> Result<Vec<DecodedBalanceLock>, subxt::error::StorageError> {
    let storage_addr = subxt::dynamic::storage::<_, ()>("Balances", "Locks");
    let account_bytes: [u8; 32] = *account.as_ref();

    let Some(value) = client_at_block
        .storage()
        .try_fetch(storage_addr, (account_bytes,))
        .await?
    else {
        return Ok(Vec::new());
    };

    if let Some(locks) = decode_balance_locks(value.bytes()) {
        return Ok(locks);
    }

    // The fixed layout assumes a u128 `Balance`. Without this, a chain with another balance type
    // would report an account's locks as an empty list.
    if let Ok(locks) = value.decode_as::<Vec<BalanceLock>>() {
        return Ok(into_decoded_locks(locks));
    }

    warn_undecodable("Balances::Locks", value.bytes());
    Ok(Vec::new())
}

/// Get proxy definitions from `Proxy::Proxies` (`None` when absent; `Err` on fetch failure).
pub async fn get_proxy_definitions(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    account: &AccountId32,
    ss58_prefix: u16,
) -> Result<Option<(Vec<DecodedProxyDefinition>, u128)>, subxt::error::StorageError> {
    use sp_core::crypto::Ss58Codec;

    let storage_addr = subxt::dynamic::storage::<_, ()>("Proxy", "Proxies");
    let account_bytes: [u8; 32] = *account.as_ref();

    let Some(value) = client_at_block
        .storage()
        .try_fetch(storage_addr, (account_bytes,))
        .await?
    else {
        return Ok(None);
    };

    // Metadata first: the proxy types are the runtime's own enum, and the deposit has the width of
    // the chain's `Balance`.
    if let Ok((proxies, deposit)) = value.decode_as::<(Vec<ProxyDefinitionNamed>, u128)>()
        && let Some(proxies) = proxies
            .into_iter()
            .map(|p| {
                Some(DecodedProxyDefinition {
                    delegate: AccountId32::from(p.delegate)
                        .to_ss58check_with_version(ss58_prefix.into()),
                    proxy_type: variant_name(&p.proxy_type)?,
                    delay: p.delay,
                })
            })
            .collect::<Option<Vec<_>>>()
    {
        return Ok(Some((proxies, deposit)));
    }

    // Fixed layout, for blocks whose metadata does not describe the entry this way.
    if let Some(decoded) = decode_proxy_definitions(value.bytes(), ss58_prefix) {
        return Ok(Some(decoded));
    }

    warn_undecodable("Proxy::Proxies", value.bytes());
    Ok(None)
}

/// Get vesting schedules from `Vesting::Vesting` (empty when absent; `Err` on fetch failure).
pub async fn get_vesting_schedules(
    client_at_block: &OnlineClientAtBlock<SubstrateConfig>,
    account: &AccountId32,
) -> Result<Vec<DecodedVestingInfo>, subxt::error::StorageError> {
    let Some(raw_bytes) = try_fetch_storage(client_at_block, "Vesting", "Vesting", account).await?
    else {
        return Ok(Vec::new());
    };

    Ok(decode_vesting_schedules(&raw_bytes).unwrap_or_default())
}

// ================================================================================================
// Decoding Functions
// ================================================================================================

/// Log storage bytes we fetched but could not decode: byte length plus the first 32 bytes as hex.
///
/// An unrecognized layout yields `None`, and for locks, proxies and vesting
/// that degrades to an empty field with HTTP 200 rather than failing the request. This log line is
/// therefore the only signal that a runtime upgrade changed a layout we thought we understood.
fn warn_undecodable(what: &str, raw_bytes: &[u8]) {
    let len = raw_bytes.len();
    tracing::warn!(
        "Failed to decode {} ({} bytes): 0x{}",
        what,
        len,
        hex::encode(&raw_bytes[..len.min(32)])
    );
}

fn decode_account_info(raw_bytes: &[u8]) -> Option<DecodedAccountData> {
    let len = raw_bytes.len();

    /// Helper: build `DecodedAccountData` for modern runtimes (frozen field, no misc/fee frozen).
    fn modern_data(nonce: u32, data: &AccountDataModern) -> DecodedAccountData {
        DecodedAccountData {
            nonce,
            free: data.free,
            reserved: data.reserved,
            misc_frozen: None,
            fee_frozen: None,
            frozen: Some(data.frozen),
        }
    }

    /// Helper: build `DecodedAccountData` for legacy runtimes (misc_frozen/fee_frozen, no frozen).
    fn legacy_data(nonce: u32, data: &AccountDataLegacy) -> DecodedAccountData {
        DecodedAccountData {
            nonce,
            free: data.free,
            reserved: data.reserved,
            misc_frozen: Some(data.misc_frozen),
            fee_frozen: Some(data.fee_frozen),
            frozen: None,
        }
    }

    // Modern format: nonce + consumers + providers + sufficients + {free, reserved, frozen, flags}
    // Layout: 4+4+4+4 + 16+16+16+16 = 80 bytes
    //
    // NOTE: Both AccountInfoModern and AccountInfoLegacy are 80 bytes with identical SCALE
    // layouts — the last two u128 fields are (frozen, flags) vs (misc_frozen, fee_frozen).
    // We try Modern first because the `frozen` field was introduced in the same runtime
    // upgrade that added `sufficients` (making the struct 80 bytes). Any 80-byte payload
    // from a runtime that still used misc_frozen/fee_frozen would also have `sufficients`,
    // which didn't exist before `frozen` — so Modern-first is correct in practice.
    // The Legacy fallback exists only as a safety net for unexpected edge cases.
    if len == 80 {
        if let Ok(info) = AccountInfoModern::decode(&mut &raw_bytes[..]) {
            return Some(modern_data(info.nonce, &info.data));
        }
        if let Ok(info) = AccountInfoLegacy::decode(&mut &raw_bytes[..]) {
            return Some(legacy_data(info.nonce, &info.data));
        }
    }

    // Pre-sufficients format (before runtime v29): nonce + consumers + providers + {free, reserved, misc_frozen, fee_frozen}
    // Layout: 4+4+4 + 16+16+16+16 = 76 bytes
    if len == 76
        && let Ok(info) = AccountInfoPreSufficients::decode(&mut &raw_bytes[..])
    {
        return Some(legacy_data(info.nonce, &info.data));
    }

    // Earliest format (single refcount): nonce + refcount(u8) + {free, reserved, misc_frozen, fee_frozen}
    // Layout: 4+1 + 16+16+16+16 = 69 bytes
    if len == 69
        && let Ok(info) = AccountInfoRefcount::decode(&mut &raw_bytes[..])
    {
        return Some(legacy_data(info.nonce, &info.data));
    }

    // No fallback: we only decode sizes we explicitly understand (69, 76, 80).
    // SCALE Decode will happily consume a prefix of a larger buffer, which would silently
    // return wrong data for future runtime layouts with a different size.
    None
}

/// Build the account data from an `AccountInfo` decoded with the chain metadata.
///
/// Fields are read by name, so this does not depend on the width of the balance type or on the
/// reference counters the runtime has. `None` if a field this API reports is missing.
fn account_data_from_value<T>(info: &Value<T>) -> Option<DecodedAccountData> {
    let nonce = u32::try_from(uint_at(info, "nonce")?).ok()?;
    let data = info.at("data")?;
    let free = uint_at(data, "free")?;
    let reserved = uint_at(data, "reserved")?;

    if let Some(frozen) = uint_at(data, "frozen") {
        return Some(DecodedAccountData {
            nonce,
            free,
            reserved,
            misc_frozen: None,
            fee_frozen: None,
            frozen: Some(frozen),
        });
    }

    Some(DecodedAccountData {
        nonce,
        free,
        reserved,
        misc_frozen: Some(uint_at(data, "misc_frozen")?),
        fee_frozen: Some(uint_at(data, "fee_frozen")?),
        frozen: None,
    })
}

fn uint_at<T>(value: &Value<T>, field: &str) -> Option<u128> {
    as_uint(value.at(field)?)
}

/// Read an unsigned integer, looking through newtype wrappers such as `struct Balance(u64)`.
fn as_uint<T>(value: &Value<T>) -> Option<u128> {
    match &value.value {
        ValueDef::Composite(Composite::Unnamed(fields)) if fields.len() == 1 => as_uint(&fields[0]),
        _ => value.as_u128(),
    }
}

fn decode_balance_locks(raw_bytes: &[u8]) -> Option<Vec<DecodedBalanceLock>> {
    Vec::<BalanceLock>::decode(&mut &raw_bytes[..])
        .ok()
        .map(into_decoded_locks)
}

fn into_decoded_locks(locks: Vec<BalanceLock>) -> Vec<DecodedBalanceLock> {
    locks
        .into_iter()
        .map(|lock| DecodedBalanceLock {
            id: format!("0x{}", hex::encode(lock.id)),
            amount: lock.amount,
            reasons: lock.reasons.as_str().to_string(),
        })
        .collect()
}

fn decode_proxy_definitions(
    raw_bytes: &[u8],
    ss58_prefix: u16,
) -> Option<(Vec<DecodedProxyDefinition>, u128)> {
    use sp_core::crypto::Ss58Codec;

    // Proxy storage is (Vec<ProxyDefinition>, deposit)
    // Try decoding the tuple
    let (proxies, deposit) = <(Vec<ProxyDefinition>, u128)>::decode(&mut &raw_bytes[..]).ok()?;

    let decoded_proxies = proxies
        .into_iter()
        .map(|p| {
            let delegate =
                AccountId32::from(p.delegate).to_ss58check_with_version(ss58_prefix.into());
            DecodedProxyDefinition {
                delegate,
                proxy_type: proxy_type_name(p.proxy_type),
                delay: p.delay,
            }
        })
        .collect();

    Some((decoded_proxies, deposit))
}

/// Name of a fieldless enum variant, such as a proxy type.
fn variant_name<T>(value: &Value<T>) -> Option<String> {
    match &value.value {
        ValueDef::Variant(variant) => Some(variant.name.clone()),
        _ => None,
    }
}

/// Proxy type names by variant index on Polkadot/Kusama runtimes, for when the metadata cannot
/// name them.
fn proxy_type_name(index: u8) -> String {
    match index {
        0 => "Any".to_string(),
        1 => "NonTransfer".to_string(),
        2 => "Governance".to_string(),
        3 => "Staking".to_string(),
        4 => "IdentityJudgement".to_string(),
        5 => "CancelProxy".to_string(),
        6 => "Auction".to_string(),
        7 => "NominationPools".to_string(),
        _ => format!("Unknown({})", index),
    }
}

fn decode_vesting_schedules(raw_bytes: &[u8]) -> Option<Vec<DecodedVestingInfo>> {
    // Vesting storage is Option<Vec<VestingInfo>> or Vec<VestingInfo>
    // Try Vec first
    if let Ok(schedules) = Vec::<VestingInfo>::decode(&mut &raw_bytes[..]) {
        return Some(
            schedules
                .into_iter()
                .map(|v| DecodedVestingInfo {
                    locked: v.locked,
                    per_block: v.per_block,
                    starting_block: v.starting_block,
                })
                .collect(),
        );
    }

    // Try Option<Vec<VestingInfo>>
    if let Ok(Some(schedules)) = Option::<Vec<VestingInfo>>::decode(&mut &raw_bytes[..]) {
        return Some(
            schedules
                .into_iter()
                .map(|v| DecodedVestingInfo {
                    locked: v.locked,
                    per_block: v.per_block,
                    starting_block: v.starting_block,
                })
                .collect(),
        );
    }

    // Both layouts exhausted. Reaching here means the bytes are neither a `Vec<VestingInfo>` nor
    // an `Option<Vec<VestingInfo>>` — a legitimately empty schedule list decodes as an empty `Vec`
    // in the first attempt, so this is a real layout mismatch, not "no vesting".
    warn_undecodable("Vesting::Vesting", raw_bytes);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manually build a raw 80-byte modern AccountInfo payload (SCALE little-endian):
    /// nonce(4) + consumers(4) + providers(4) + sufficients(4) + free(16) + reserved(16) + frozen(16) + flags(16)
    fn build_modern_bytes(nonce: u32, free: u128, reserved: u128, frozen: u128) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // consumers
        buf.extend_from_slice(&1u32.to_le_bytes()); // providers
        buf.extend_from_slice(&0u32.to_le_bytes()); // sufficients
        buf.extend_from_slice(&free.to_le_bytes());
        buf.extend_from_slice(&reserved.to_le_bytes());
        buf.extend_from_slice(&frozen.to_le_bytes());
        buf.extend_from_slice(&0u128.to_le_bytes()); // flags
        assert_eq!(buf.len(), 80);
        buf
    }

    /// Manually build a raw 76-byte pre-sufficients AccountInfo payload:
    /// nonce(4) + consumers(4) + providers(4) + free(16) + reserved(16) + misc_frozen(16) + fee_frozen(16)
    fn build_pre_sufficients_bytes(
        nonce: u32,
        free: u128,
        reserved: u128,
        misc_frozen: u128,
        fee_frozen: u128,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(76);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // consumers
        buf.extend_from_slice(&1u32.to_le_bytes()); // providers
        buf.extend_from_slice(&free.to_le_bytes());
        buf.extend_from_slice(&reserved.to_le_bytes());
        buf.extend_from_slice(&misc_frozen.to_le_bytes());
        buf.extend_from_slice(&fee_frozen.to_le_bytes());
        assert_eq!(buf.len(), 76);
        buf
    }

    /// Manually build a raw 69-byte refcount-era AccountInfo payload:
    /// nonce(4) + refcount(1) + free(16) + reserved(16) + misc_frozen(16) + fee_frozen(16)
    fn build_refcount_bytes(
        nonce: u32,
        refcount: u8,
        free: u128,
        reserved: u128,
        misc_frozen: u128,
        fee_frozen: u128,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(69);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.push(refcount);
        buf.extend_from_slice(&free.to_le_bytes());
        buf.extend_from_slice(&reserved.to_le_bytes());
        buf.extend_from_slice(&misc_frozen.to_le_bytes());
        buf.extend_from_slice(&fee_frozen.to_le_bytes());
        assert_eq!(buf.len(), 69);
        buf
    }

    #[test]
    fn test_decode_modern_account_info_80_bytes() {
        let bytes = build_modern_bytes(42, 1_000_000_000_000, 500_000, 100_000);

        let result = decode_account_info(&bytes).expect("should decode modern format");
        assert_eq!(result.nonce, 42);
        assert_eq!(result.free, 1_000_000_000_000);
        assert_eq!(result.reserved, 500_000);
        assert_eq!(result.frozen, Some(100_000));
        assert_eq!(result.misc_frozen, None);
        assert_eq!(result.fee_frozen, None);
    }

    #[test]
    fn test_decode_pre_sufficients_account_info_76_bytes() {
        // Simulates Polkadot blocks between runtime v29 introduction and sufficients addition
        let bytes = build_pre_sufficients_bytes(79219, 466_398_602_382_908_664, 0, 0, 0);

        let result =
            decode_account_info(&bytes).expect("should decode pre-sufficients format (76 bytes)");
        assert_eq!(result.nonce, 79219);
        assert_eq!(result.free, 466_398_602_382_908_664);
        assert_eq!(result.reserved, 0);
        assert_eq!(result.misc_frozen, Some(0));
        assert_eq!(result.fee_frozen, Some(0));
        assert_eq!(result.frozen, None);
    }

    #[test]
    fn test_decode_refcount_account_info_69_bytes() {
        // Simulates earliest Polkadot blocks (e.g. block 20000)
        let bytes = build_refcount_bytes(1, 0, 1_000_000_000_000_000, 0, 0, 0);

        let result = decode_account_info(&bytes).expect("should decode refcount format (69 bytes)");
        assert_eq!(result.nonce, 1);
        assert_eq!(result.free, 1_000_000_000_000_000);
        assert_eq!(result.reserved, 0);
        assert_eq!(result.misc_frozen, Some(0));
        assert_eq!(result.fee_frozen, Some(0));
        assert_eq!(result.frozen, None);
    }

    #[test]
    fn test_decode_empty_bytes_returns_none() {
        let result = decode_account_info(&[]);
        assert!(result.is_none(), "empty bytes should return None");
    }

    #[test]
    fn test_decode_short_bytes_returns_none() {
        let result = decode_account_info(&[0u8; 10]);
        assert!(result.is_none(), "too-short bytes should return None");
    }

    #[test]
    fn test_decode_pre_sufficients_with_nonzero_frozen() {
        // Polkadot block ~3574738 era: pre-sufficients with actual frozen balances
        let bytes = build_pre_sufficients_bytes(
            47101,
            4_533_720_292_342_876_436_692_992u128,
            0,
            100_000,
            50_000,
        );

        let result =
            decode_account_info(&bytes).expect("should decode pre-sufficients with nonzero frozen");
        assert_eq!(result.nonce, 47101);
        assert_eq!(result.free, 4_533_720_292_342_876_436_692_992u128);
        assert_eq!(result.misc_frozen, Some(100_000));
        assert_eq!(result.fee_frozen, Some(50_000));
        assert_eq!(result.frozen, None);
    }

    #[test]
    fn test_decode_refcount_with_nonzero_refcount() {
        // Earliest Polkadot blocks had refcount > 0 for active accounts
        let bytes = build_refcount_bytes(5, 2, 500_000_000_000, 100_000_000, 0, 0);

        let result =
            decode_account_info(&bytes).expect("should decode refcount format with refcount > 0");
        assert_eq!(result.nonce, 5);
        assert_eq!(result.free, 500_000_000_000);
        assert_eq!(result.reserved, 100_000_000);
    }

    #[test]
    fn test_size_invariants() {
        // Verify the struct sizes match our expectations
        assert_eq!(build_modern_bytes(0, 0, 0, 0).len(), 80);
        assert_eq!(build_pre_sufficients_bytes(0, 0, 0, 0, 0).len(), 76);
        assert_eq!(build_refcount_bytes(0, 0, 0, 0, 0, 0).len(), 69);
    }
}

/// Tests for the metadata-driven `AccountInfo` and `Balances::Locks` decoding.
#[cfg(test)]
mod metadata_decode_tests {
    use super::*;
    use parity_scale_codec::Encode;
    use scale_info::PortableRegistry;

    /// `AccountInfo` of a chain whose `Balance` is u64, as on Bittensor.
    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountInfoU64 {
        nonce: u32,
        consumers: u32,
        providers: u32,
        sufficients: u32,
        data: AccountDataU64,
    }

    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountDataU64 {
        free: u64,
        reserved: u64,
        frozen: u64,
        flags: u128,
    }

    /// Same, with the balance wrapped in a newtype.
    #[derive(Encode, scale_info::TypeInfo)]
    struct WrappedBalance(u64);

    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountInfoWrapped {
        nonce: u32,
        data: AccountDataWrapped,
    }

    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountDataWrapped {
        free: WrappedBalance,
        reserved: WrappedBalance,
        frozen: WrappedBalance,
    }

    /// Pre-`frozen` runtime with a u64 `Balance`.
    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountInfoLegacyU64 {
        nonce: u32,
        data: AccountDataLegacyU64,
    }

    #[derive(Encode, scale_info::TypeInfo)]
    struct AccountDataLegacyU64 {
        free: u64,
        reserved: u64,
        misc_frozen: u64,
        fee_frozen: u64,
    }

    /// Decode `value` the way `get_account_data` does: against the type's own metadata.
    fn decode_with_metadata<T: Encode + scale_info::TypeInfo + 'static>(
        value: &T,
    ) -> Option<DecodedAccountData> {
        let mut registry = scale_info::Registry::new();
        let type_id = registry.register_type(&scale_info::meta_type::<T>()).id;
        let registry: PortableRegistry = registry.into();

        let bytes = value.encode();
        let decoded = scale_value::scale::decode_as_type(&mut &bytes[..], type_id, &registry)
            .expect("bytes should decode against their own type");
        account_data_from_value(&decoded)
    }

    /// An account read from Bittensor mainnet (spec 491): nonce 1981, free 75057346.
    fn bittensor_account() -> AccountInfoU64 {
        AccountInfoU64 {
            nonce: 1981,
            consumers: 0,
            providers: 1,
            sufficients: 0,
            data: AccountDataU64 {
                free: 75_057_346,
                reserved: 0,
                frozen: 0,
                flags: 1 << 127,
            },
        }
    }

    #[test]
    fn u64_balance_account_matches_no_fixed_layout() {
        let bytes = bittensor_account().encode();
        assert_eq!(bytes.len(), 56);
        assert!(decode_account_info(&bytes).is_none());
    }

    #[test]
    fn u64_balance_account_decodes_with_metadata() {
        let data = decode_with_metadata(&bittensor_account()).expect("should decode");
        assert_eq!(data.nonce, 1981);
        assert_eq!(data.free, 75_057_346);
        assert_eq!(data.reserved, 0);
        assert_eq!(data.frozen, Some(0));
        assert_eq!(data.misc_frozen, None);
        assert_eq!(data.fee_frozen, None);
    }

    #[test]
    fn u64_balance_amounts_are_not_mixed_up() {
        let mut account = bittensor_account();
        account.data.reserved = 1_000;
        account.data.frozen = 57_346;

        let data = decode_with_metadata(&account).expect("should decode");
        assert_eq!(data.free, 75_057_346);
        assert_eq!(data.reserved, 1_000);
        assert_eq!(data.frozen, Some(57_346));
    }

    #[test]
    fn newtype_balance_decodes_with_metadata() {
        let account = AccountInfoWrapped {
            nonce: 7,
            data: AccountDataWrapped {
                free: WrappedBalance(500),
                reserved: WrappedBalance(20),
                frozen: WrappedBalance(3),
            },
        };

        let data = decode_with_metadata(&account).expect("should decode");
        assert_eq!(data.nonce, 7);
        assert_eq!(data.free, 500);
        assert_eq!(data.reserved, 20);
        assert_eq!(data.frozen, Some(3));
    }

    #[test]
    fn legacy_frozen_fields_decode_with_metadata() {
        let account = AccountInfoLegacyU64 {
            nonce: 2,
            data: AccountDataLegacyU64 {
                free: 900,
                reserved: 10,
                misc_frozen: 40,
                fee_frozen: 30,
            },
        };

        let data = decode_with_metadata(&account).expect("should decode");
        assert_eq!(data.free, 900);
        assert_eq!(data.frozen, None);
        assert_eq!(data.misc_frozen, Some(40));
        assert_eq!(data.fee_frozen, Some(30));
    }

    /// `Balances::Locks` of a chain whose `Balance` is u64: 17 bytes per lock, against 25.
    #[test]
    fn u64_balance_locks_decode_with_metadata() {
        use scale_decode::DecodeAsType;

        #[derive(Encode, scale_info::TypeInfo)]
        struct LockU64 {
            id: [u8; 8],
            amount: u64,
            reasons: ReasonsU64,
        }

        #[derive(Encode, scale_info::TypeInfo)]
        #[allow(dead_code)]
        enum ReasonsU64 {
            Fee,
            Misc,
            All,
        }

        let locks = vec![
            LockU64 {
                id: *b"staking ",
                amount: 1_000,
                reasons: ReasonsU64::All,
            },
            LockU64 {
                id: *b"vesting ",
                amount: 57_346,
                reasons: ReasonsU64::Misc,
            },
        ];
        let bytes = locks.encode();
        assert!(decode_balance_locks(&bytes).is_none());

        let mut registry = scale_info::Registry::new();
        let type_id = registry
            .register_type(&scale_info::meta_type::<Vec<LockU64>>())
            .id;
        let registry: PortableRegistry = registry.into();

        let decoded = Vec::<BalanceLock>::decode_as_type(&mut &bytes[..], type_id, &registry)
            .map(into_decoded_locks)
            .expect("should decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].id, format!("0x{}", hex::encode(b"staking ")));
        assert_eq!(decoded[0].amount, 1_000);
        assert_eq!(decoded[0].reasons, "All");
        assert_eq!(decoded[1].amount, 57_346);
        assert_eq!(decoded[1].reasons, "Misc");
    }

    /// `Proxy::Proxies` of a chain with a u64 deposit and its own proxy types, as on Bittensor.
    #[test]
    fn u64_deposit_proxies_decode_with_metadata() {
        use scale_decode::DecodeAsType;

        #[derive(Encode, scale_info::TypeInfo)]
        struct ProxyU64 {
            delegate: [u8; 32],
            proxy_type: ChainProxyType,
            delay: u32,
        }

        #[derive(Encode, scale_info::TypeInfo)]
        #[allow(dead_code)]
        enum ChainProxyType {
            Any,
            Owner,
            ChildKeys,
        }

        let stored = (
            vec![ProxyU64 {
                delegate: [7u8; 32],
                proxy_type: ChainProxyType::ChildKeys,
                delay: 5,
            }],
            93_000u64,
        );
        let bytes = stored.encode();
        assert!(decode_proxy_definitions(&bytes, 42).is_none());

        let mut registry = scale_info::Registry::new();
        let type_id = registry
            .register_type(&scale_info::meta_type::<(Vec<ProxyU64>, u64)>())
            .id;
        let registry: PortableRegistry = registry.into();

        let (proxies, deposit) = <(Vec<ProxyDefinitionNamed>, u128)>::decode_as_type(
            &mut &bytes[..],
            type_id,
            &registry,
        )
        .expect("should decode");
        assert_eq!(deposit, 93_000);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].delegate, [7u8; 32]);
        assert_eq!(proxies[0].delay, 5);
        assert_eq!(
            variant_name(&proxies[0].proxy_type).as_deref(),
            Some("ChildKeys")
        );
    }

    #[test]
    fn value_without_balances_is_rejected() {
        #[derive(Encode, scale_info::TypeInfo)]
        struct NotAnAccount {
            nonce: u32,
            data: u64,
        }

        assert!(decode_with_metadata(&NotAnAccount { nonce: 1, data: 2 }).is_none());
    }
}

/// End-to-end tests for `get_account_data_or_default` driven over a mock RPC client.
///
/// These guard the false-zero regression: a failed `System::Account` fetch must surface
/// as an error, while a present or genuinely-absent account must decode correctly.
#[cfg(test)]
mod rpc_fetch_tests {
    use super::*;
    use crate::test_fixtures::{TEST_BLOCK_NUMBER, mock_rpc_client_builder, online_client};
    use subxt_rpcs::client::mock_rpc_client::Json as MockJson;

    fn test_account() -> AccountId32 {
        AccountId32::new([1u8; 32])
    }

    /// Build an 80-byte modern `AccountInfo` payload with the given free balance.
    fn modern_account_bytes(free: u128) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&0u32.to_le_bytes()); // nonce
        buf.extend_from_slice(&1u32.to_le_bytes()); // consumers
        buf.extend_from_slice(&1u32.to_le_bytes()); // providers
        buf.extend_from_slice(&0u32.to_le_bytes()); // sufficients
        buf.extend_from_slice(&free.to_le_bytes()); // free
        buf.extend_from_slice(&0u128.to_le_bytes()); // reserved
        buf.extend_from_slice(&0u128.to_le_bytes()); // frozen
        buf.extend_from_slice(&0u128.to_le_bytes()); // flags
        buf
    }

    #[tokio::test]
    async fn present_account_returns_real_balance() {
        let free = 100_000_000u128;
        let hex = format!("0x{}", hex::encode(modern_account_bytes(free)));
        let mock = mock_rpc_client_builder()
            .method_handler("state_getStorage", move |_params| {
                let hex = hex.clone();
                async move { MockJson(hex) }
            })
            .build();

        let client = online_client(mock).await;
        let at = client
            .at_block(TEST_BLOCK_NUMBER)
            .await
            .expect("at_block failed");

        let data = get_account_data_or_default(&at, &test_account())
            .await
            .expect("a successful fetch must not error");
        assert_eq!(data.free, free);
    }

    #[tokio::test]
    async fn absent_account_yields_zero() {
        // `null` response => subxt substitutes the metadata default for `System::Account`
        // (`try_fetch` ends in `.or_else(|| self.default_value())`), so this decodes a zeroed
        // AccountInfo => legitimate zero balance. The `Ok(None)` fallback in
        // `get_account_data_or_default` is a safety net for metadata without a default and is
        // not reachable through this path.
        let mock = mock_rpc_client_builder()
            .method_handler("state_getStorage", async |_params| {
                MockJson(Option::<String>::None)
            })
            .build();

        let client = online_client(mock).await;
        let at = client
            .at_block(TEST_BLOCK_NUMBER)
            .await
            .expect("at_block failed");

        let data = get_account_data_or_default(&at, &test_account())
            .await
            .expect("an absent account is not an error");
        assert_eq!(data.free, 0);
    }

    /// Regression guard for the Binance false-zero incident: a transient fetch failure
    /// must be an error, NOT a fabricated `free: 0`. This fails against the previous
    /// `.ok()?` implementation (which returned zeroed data) and passes after the fix.
    #[tokio::test]
    async fn transient_fetch_error_is_not_false_zero() {
        let mock = mock_rpc_client_builder()
            .method_handler("state_getStorage", async |_params| {
                Err::<MockJson<String>, subxt_rpcs::Error>(subxt_rpcs::Error::Client(Box::new(
                    std::io::Error::other("simulated transient RPC failure"),
                )))
            })
            .build();

        let client = online_client(mock).await;
        let at = client
            .at_block(TEST_BLOCK_NUMBER)
            .await
            .expect("at_block failed");

        let result = get_account_data_or_default(&at, &test_account()).await;
        assert!(
            result.is_err(),
            "a failed storage fetch must surface as an error, not free:0"
        );
    }

    /// Present-but-undecodable bytes must error, not become `free: 0`.
    #[tokio::test]
    async fn undecodable_bytes_are_not_false_zero() {
        // 10 bytes: matches no known layout.
        let hex = format!("0x{}", hex::encode([0u8; 10]));
        let mock = mock_rpc_client_builder()
            .method_handler("state_getStorage", move |_params| {
                let hex = hex.clone();
                async move { MockJson(hex) }
            })
            .build();

        let client = online_client(mock).await;
        let at = client
            .at_block(TEST_BLOCK_NUMBER)
            .await
            .expect("at_block failed");

        let result = get_account_data_or_default(&at, &test_account()).await;
        assert!(
            result.is_err(),
            "present-but-undecodable bytes must surface as an error, not free:0"
        );
    }
}
