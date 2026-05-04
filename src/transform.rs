use crate::faker_dispatch::{
    faker_string_with_rng, pii_first_name, pii_full_name, pii_last_name, pii_phone_number,
    pii_safe_email, resolved_locale_key,
};
use crate::scan::luhn_valid;
use crate::settings::{AnonymizerSpec, ResolvedConfig};
use chrono::Timelike;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime};
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
struct DomainMapping {
    forward: HashMap<String, Replacement>,
    reverse: HashMap<String, String>,
}

/// Security profile controlling cryptographic choices for anonymization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SecurityProfile {
    /// xorshift64* PRNG; SHA-256 for deterministic hashing. Suitable for most use cases.
    #[default]
    Standard,
    /// OS CSPRNG for random strategies; HMAC-SHA-256 keyed by the configured salt for
    /// deterministic hashing. Recommended for adversarial risk environments.
    Hardened,
}

pub struct AnonymizerRegistry {
    pub default_salt: Option<String>,
    pub security_profile: SecurityProfile,
    domain_mappings: RefCell<HashMap<String, DomainMapping>>,
    /// Reused for `faker`, `phone`, and built-in PII strategies on the random (non-domain) path.
    faker_rng: RefCell<StdRng>,
    /// Count of domain-map lookups that returned a cached pseudonym (for `--stats` / profiling).
    pub domain_cache_hits: AtomicU64,
    /// Count of domain-map lookups that computed a new pseudonym.
    pub domain_cache_misses: AtomicU64,
}

static mut RNG_SEED_OVERRIDE: Option<u64> = None;
static HARDENED_PROFILE_ACTIVE: AtomicBool = AtomicBool::new(false);
const MAX_DOMAIN_UNIQUENESS_ATTEMPTS: u64 = 4096;

/// Enable or disable the hardened security profile process-wide.
///
/// When active:
/// - Random strategies use OS CSPRNG instead of xorshift64*.
/// - Deterministic strategies use HMAC-SHA-256 instead of plain SHA-256.
/// - The `hash` strategy uses HMAC-SHA-256 keyed by the configured salt.
pub fn set_hardened_profile(active: bool) {
    HARDENED_PROFILE_ACTIVE.store(active, Ordering::Relaxed);
}

fn is_hardened_profile() -> bool {
    HARDENED_PROFILE_ACTIVE.load(Ordering::Relaxed)
}

/// Fill `buf` with cryptographically secure random bytes from the OS entropy source.
fn csprng_fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("CSPRNG failure: OS random number generator is unavailable");
}

impl AnonymizerRegistry {
    pub fn from_config(cfg: &ResolvedConfig) -> Self {
        Self {
            default_salt: cfg.salt.clone(),
            security_profile: SecurityProfile::Standard,
            domain_mappings: RefCell::new(HashMap::new()),
            faker_rng: RefCell::new(make_random_rng()),
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Replacement {
    /// The replacement value without surrounding SQL quotes
    pub value: Arc<str>,
    /// If true, force render as quoted literal
    pub force_quoted: bool,
    /// If true, render as NULL
    pub is_null: bool,
}

impl Replacement {
    pub fn null() -> Self {
        Self {
            value: Arc::from(""),
            force_quoted: false,
            is_null: true,
        }
    }
    pub fn quoted<V: Into<String>>(v: V) -> Self {
        Self {
            value: Arc::from(v.into()),
            force_quoted: true,
            is_null: false,
        }
    }
    pub fn unquoted<V: Into<String>>(v: V) -> Self {
        Self {
            value: Arc::from(v.into()),
            force_quoted: false,
            is_null: false,
        }
    }
}

pub fn apply_anonymizer(
    registry: &AnonymizerRegistry,
    spec: &AnonymizerSpec,
    original_unescaped: Option<&str>,
    column_max_len: Option<usize>,
) -> Replacement {
    let mut replacement = if let Some(domain_key) = normalized_domain(spec) {
        apply_domain_anonymizer(registry, spec, original_unescaped, &domain_key)
    } else {
        apply_random_anonymizer(registry, spec, original_unescaped)
    };
    if let Some(max_len) = column_max_len {
        if !replacement.is_null && should_enforce_max_len(spec.strategy.as_str()) {
            replacement.value = truncate_arc_str(replacement.value.clone(), max_len);
        }
    }
    replacement
}

fn normalized_domain(spec: &AnonymizerSpec) -> Option<String> {
    spec.domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn apply_domain_anonymizer(
    registry: &AnonymizerRegistry,
    spec: &AnonymizerSpec,
    original_unescaped: Option<&str>,
    domain_key: &str,
) -> Replacement {
    let Some(original_value) = original_unescaped else {
        // NULL inputs have no source value to map, so preserve NULL. This is the correct behavior
        // for nullable FK columns: a NULL FK (no relationship) should remain NULL after
        // anonymization so that referential integrity is not accidentally fabricated.
        return Replacement::null();
    };

    let mut mappings = registry.domain_mappings.borrow_mut();
    let mapping = mappings.entry(domain_key.to_string()).or_default();
    if let Some(existing) = mapping.forward.get(original_value) {
        registry.domain_cache_hits.fetch_add(1, Ordering::Relaxed);
        return existing.clone();
    }
    registry.domain_cache_misses.fetch_add(1, Ordering::Relaxed);

    let enforce_unique = spec.unique_within_domain.unwrap_or(false);
    let mut collision_index: u64 = 0;
    loop {
        let candidate = apply_deterministic_anonymizer(
            registry,
            spec,
            Some(original_value),
            domain_key,
            collision_index,
        );
        if !enforce_unique {
            let candidate_key = uniqueness_key(&candidate);
            mapping
                .reverse
                .entry(candidate_key)
                .or_insert_with(|| original_value.to_string());
            mapping
                .forward
                .insert(original_value.to_string(), candidate.clone());
            return candidate;
        }
        let candidate_key = uniqueness_key(&candidate);
        match mapping.reverse.get(&candidate_key) {
            Some(previous_source) if previous_source != original_value => {
                if collision_index >= MAX_DOMAIN_UNIQUENESS_ATTEMPTS {
                    mapping
                        .forward
                        .insert(original_value.to_string(), candidate.clone());
                    return candidate;
                }
                collision_index = collision_index.saturating_add(1);
                continue;
            }
            _ => {
                mapping
                    .reverse
                    .insert(candidate_key, original_value.to_string());
                mapping
                    .forward
                    .insert(original_value.to_string(), candidate.clone());
                return candidate;
            }
        }
    }
}

fn uniqueness_key(replacement: &Replacement) -> String {
    if replacement.is_null {
        "__NULL__".to_string()
    } else {
        replacement.value.as_ref().to_string()
    }
}

/// Seed a `StdRng` using 32 random bytes from the xorshift PRNG (standard mode) or OS CSPRNG
/// (hardened mode). Used to bridge the internal PRNG into the `fake` crate.
fn make_random_rng() -> StdRng {
    let mut seed = [0u8; 32];
    if is_hardened_profile() {
        csprng_fill(&mut seed);
    } else {
        for chunk in seed.chunks_mut(4) {
            let r = random_u32();
            let bytes = r.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    StdRng::from_seed(seed)
}

/// Seed a `StdRng` from the first 32 bytes of a `DeterministicByteStream`.
fn make_deterministic_rng(stream: &mut DeterministicByteStream) -> StdRng {
    let mut seed = [0u8; 32];
    for byte in &mut seed {
        *byte = stream.next_u8();
    }
    StdRng::from_seed(seed)
}

fn quoted_pii_string(
    registry: &AnonymizerRegistry,
    spec: &AnonymizerSpec,
    f: impl FnOnce(&str, &mut StdRng) -> String,
) -> Replacement {
    let loc = resolved_locale_key(spec);
    let mut rng = registry.faker_rng.borrow_mut();
    Replacement::quoted(f(loc, &mut rng))
}

fn apply_random_anonymizer(
    registry: &AnonymizerRegistry,
    spec: &AnonymizerSpec,
    original_unescaped: Option<&str>,
) -> Replacement {
    let as_string = spec.as_string.unwrap_or(false);
    match spec.strategy.as_str() {
        "null" => Replacement::null(),
        "redact" => {
            if as_string {
                Replacement::quoted("REDACTED")
            } else {
                Replacement::unquoted("REDACTED")
            }
        }
        "blank" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::quoted("")
            }
        }
        "empty_array" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::unquoted("[]")
            }
        }
        "empty_object" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::unquoted("{}")
            }
        }
        "uuid" => {
            let id = pseudo_uuid_v4();
            if as_string {
                Replacement::quoted(id)
            } else {
                Replacement::unquoted(id)
            }
        }
        "hash" => {
            let hex = if registry.security_profile == SecurityProfile::Hardened {
                // Hardened: HMAC-SHA-256 keyed by salt for proper domain separation.
                // A non-empty salt is guaranteed by startup validation in main().
                let key_str = spec
                    .salt
                    .as_deref()
                    .or(registry.default_salt.as_deref())
                    .expect(
                        "hardened mode requires a salt configured as HMAC key; \
                         this should have been rejected at startup",
                    );
                assert!(
                    !key_str.trim().is_empty(),
                    "hardened mode HMAC key must not be empty; \
                     this should have been rejected at startup"
                );
                let mut mac = HmacSha256::new_from_slice(key_str.as_bytes())
                    .expect("HMAC accepts any key length");
                if let Some(orig) = original_unescaped {
                    mac.update(orig.as_bytes());
                }
                format!("{:x}", mac.finalize().into_bytes())
            } else {
                let mut hasher = Sha256::new();
                if let Some(salt) = spec.salt.as_ref().or(registry.default_salt.as_ref()) {
                    hasher.update(salt.as_bytes());
                }
                if let Some(orig) = original_unescaped {
                    hasher.update(orig.as_bytes());
                }
                format!("{:x}", hasher.finalize())
            };
            if as_string {
                Replacement::quoted(hex)
            } else {
                Replacement::unquoted(hex)
            }
        }
        "faker" => {
            let mut rng = registry.faker_rng.borrow_mut();
            let value = faker_string_with_rng(spec, &mut rng).unwrap_or_else(|| {
                unreachable!(
                    "faker strategy must be validated at config load; unsupported faker should never reach apply_random_anonymizer"
                )
            });
            Replacement::quoted(value)
        }
        "email" => quoted_pii_string(registry, spec, pii_safe_email),
        "name" => quoted_pii_string(registry, spec, pii_full_name),
        "first_name" => quoted_pii_string(registry, spec, pii_first_name),
        "last_name" => quoted_pii_string(registry, spec, pii_last_name),
        "phone" => quoted_pii_string(registry, spec, pii_phone_number),
        "int_range" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let v = random_range_inclusive(min, max);
            Replacement::unquoted(v.to_string())
        }
        "decimal" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let scale = spec.scale.unwrap_or(2);
            decimal_replacement(min, max, scale, as_string, None)
        }
        "payment_card" => {
            let len = spec.length.unwrap_or(16);
            let digits = random_payment_card_digits(len);
            Replacement::quoted(digits)
        }
        "string" => {
            let len = spec.length.unwrap_or(12);
            let s = random_alnum(len).to_lowercase();
            Replacement::quoted(s)
        }
        "date_fuzz" => {
            // Parse YYYY-MM-DD and shift by days
            let days_min = spec.min_days.unwrap_or(-30);
            let days_max = spec.max_days.unwrap_or(30);
            let shift = random_range_inclusive(days_min, days_max);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_date(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else {
                    // on parse failure, keep original
                    if as_string {
                        Replacement::quoted(orig.to_string())
                    } else {
                        Replacement::unquoted(orig.to_string())
                    }
                }
            } else {
                Replacement::null()
            }
        }
        "time_fuzz" => {
            // Parse HH:MM[:SS[.fraction]] and shift seconds (wrap 24h)
            let sec_min = spec.min_seconds.unwrap_or(-300);
            let sec_max = spec.max_seconds.unwrap_or(300);
            let shift = random_range_inclusive(sec_min, sec_max);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_time(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else if as_string {
                    Replacement::quoted(orig.to_string())
                } else {
                    Replacement::unquoted(orig.to_string())
                }
            } else {
                Replacement::null()
            }
        }
        "datetime_fuzz" => {
            // Shift timestamp by seconds; preserve presence of offset and fractional seconds
            let sec_min = spec.min_seconds.unwrap_or(-86_400);
            let sec_max = spec.max_seconds.unwrap_or(86_400);
            let shift = random_range_inclusive(sec_min, sec_max);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_datetime(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else if as_string {
                    Replacement::quoted(orig.to_string())
                } else {
                    Replacement::unquoted(orig.to_string())
                }
            } else {
                Replacement::null()
            }
        }
        other => unreachable!(
            "unknown strategy '{}' reached runtime; config validation should have failed earlier",
            other
        ),
    }
}

fn apply_deterministic_anonymizer(
    registry: &AnonymizerRegistry,
    spec: &AnonymizerSpec,
    original_unescaped: Option<&str>,
    domain_key: &str,
    collision_index: u64,
) -> Replacement {
    let as_string = spec.as_string.unwrap_or(false);
    let mut stream = DeterministicByteStream::new(
        registry,
        spec,
        original_unescaped,
        domain_key,
        collision_index,
    );
    match spec.strategy.as_str() {
        "null" => Replacement::null(),
        "redact" => {
            if as_string {
                Replacement::quoted("REDACTED")
            } else {
                Replacement::unquoted("REDACTED")
            }
        }
        "blank" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::quoted("")
            }
        }
        "empty_array" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::unquoted("[]")
            }
        }
        "empty_object" => {
            if original_unescaped.is_none() {
                Replacement::null()
            } else {
                Replacement::unquoted("{}")
            }
        }
        "uuid" => {
            let id = deterministic_uuid_v4(&mut stream);
            if as_string {
                Replacement::quoted(id)
            } else {
                Replacement::unquoted(id)
            }
        }
        "hash" => {
            let hex = if registry.security_profile == SecurityProfile::Hardened {
                // Hardened: HMAC-SHA-256 keyed by salt for proper domain separation.
                // A non-empty salt is guaranteed by startup validation in main().
                let key_str = spec
                    .salt
                    .as_deref()
                    .or(registry.default_salt.as_deref())
                    .expect(
                        "hardened mode requires a salt configured as HMAC key; \
                         this should have been rejected at startup",
                    );
                assert!(
                    !key_str.trim().is_empty(),
                    "hardened mode HMAC key must not be empty; \
                     this should have been rejected at startup"
                );
                let mut mac = HmacSha256::new_from_slice(key_str.as_bytes())
                    .expect("HMAC accepts any key length");
                mac.update(b"dumpling-domain-map-v1");
                mac.update(domain_key.as_bytes());
                if let Some(orig) = original_unescaped {
                    mac.update(orig.as_bytes());
                }
                mac.update(&collision_index.to_le_bytes());
                format!("{:x}", mac.finalize().into_bytes())
            } else {
                let mut hasher = Sha256::new();
                hasher.update(b"dumpling-domain-map-v1");
                if let Some(salt) = spec.salt.as_ref().or(registry.default_salt.as_ref()) {
                    hasher.update(salt.as_bytes());
                }
                hasher.update(domain_key.as_bytes());
                if let Some(orig) = original_unescaped {
                    hasher.update(orig.as_bytes());
                }
                hasher.update(collision_index.to_le_bytes());
                format!("{:x}", hasher.finalize())
            };
            if as_string {
                Replacement::quoted(hex)
            } else {
                Replacement::unquoted(hex)
            }
        }
        "faker" => {
            let mut rng = make_deterministic_rng(&mut stream);
            let value = faker_string_with_rng(spec, &mut rng).unwrap_or_else(|| {
                unreachable!(
                    "faker strategy must be validated at config load; unsupported faker should never reach apply_deterministic_anonymizer"
                )
            });
            Replacement::quoted(value)
        }
        "email" => {
            let loc = resolved_locale_key(spec);
            let mut rng = make_deterministic_rng(&mut stream);
            Replacement::quoted(pii_safe_email(loc, &mut rng))
        }
        "name" => {
            let loc = resolved_locale_key(spec);
            let mut rng = make_deterministic_rng(&mut stream);
            Replacement::quoted(pii_full_name(loc, &mut rng))
        }
        "first_name" => {
            let loc = resolved_locale_key(spec);
            let mut rng = make_deterministic_rng(&mut stream);
            Replacement::quoted(pii_first_name(loc, &mut rng))
        }
        "last_name" => {
            let loc = resolved_locale_key(spec);
            let mut rng = make_deterministic_rng(&mut stream);
            Replacement::quoted(pii_last_name(loc, &mut rng))
        }
        "phone" => {
            let loc = resolved_locale_key(spec);
            let mut rng = make_deterministic_rng(&mut stream);
            Replacement::quoted(pii_phone_number(loc, &mut rng))
        }
        "int_range" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let v = deterministic_range_inclusive(min, max, &mut stream);
            Replacement::unquoted(v.to_string())
        }
        "decimal" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let scale = spec.scale.unwrap_or(2);
            decimal_replacement(min, max, scale, as_string, Some(&mut stream))
        }
        "payment_card" => {
            let len = spec.length.unwrap_or(16);
            let digits = deterministic_payment_card_digits(len, &mut stream);
            Replacement::quoted(digits)
        }
        "string" => {
            let len = spec.length.unwrap_or(12);
            let s = deterministic_alnum(len, &mut stream).to_lowercase();
            Replacement::quoted(s)
        }
        "date_fuzz" => {
            let days_min = spec.min_days.unwrap_or(-30);
            let days_max = spec.max_days.unwrap_or(30);
            let shift = deterministic_range_inclusive(days_min, days_max, &mut stream);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_date(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else if as_string {
                    Replacement::quoted(orig.to_string())
                } else {
                    Replacement::unquoted(orig.to_string())
                }
            } else {
                Replacement::null()
            }
        }
        "time_fuzz" => {
            let sec_min = spec.min_seconds.unwrap_or(-300);
            let sec_max = spec.max_seconds.unwrap_or(300);
            let shift = deterministic_range_inclusive(sec_min, sec_max, &mut stream);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_time(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else if as_string {
                    Replacement::quoted(orig.to_string())
                } else {
                    Replacement::unquoted(orig.to_string())
                }
            } else {
                Replacement::null()
            }
        }
        "datetime_fuzz" => {
            let sec_min = spec.min_seconds.unwrap_or(-86_400);
            let sec_max = spec.max_seconds.unwrap_or(86_400);
            let shift = deterministic_range_inclusive(sec_min, sec_max, &mut stream);
            if let Some(orig) = original_unescaped {
                if let Some(res) = fuzz_datetime(orig, shift) {
                    if as_string {
                        Replacement::quoted(res)
                    } else {
                        Replacement::unquoted(res)
                    }
                } else if as_string {
                    Replacement::quoted(orig.to_string())
                } else {
                    Replacement::unquoted(orig.to_string())
                }
            } else {
                Replacement::null()
            }
        }
        other => unreachable!(
            "unknown strategy '{}' reached runtime; config validation should have failed earlier",
            other
        ),
    }
}

struct DeterministicByteStream {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    block_index: usize,
    use_hmac: bool,
}

impl DeterministicByteStream {
    fn new(
        registry: &AnonymizerRegistry,
        spec: &AnonymizerSpec,
        original_unescaped: Option<&str>,
        domain_key: &str,
        collision_index: u64,
    ) -> Self {
        let use_hmac = registry.security_profile == SecurityProfile::Hardened;
        let seed = if use_hmac {
            // Hardened: use HMAC-SHA-256 keyed by the configured salt for proper domain
            // separation and resistance to length-extension attacks.
            // A non-empty salt is guaranteed by startup validation in main().
            let hmac_key_str = spec
                .salt
                .as_deref()
                .or(registry.default_salt.as_deref())
                .expect(
                    "hardened mode requires a salt configured as HMAC key; \
                     this should have been rejected at startup",
                );
            assert!(
                !hmac_key_str.trim().is_empty(),
                "hardened mode HMAC key must not be empty; \
                 this should have been rejected at startup"
            );
            let mut mac = HmacSha256::new_from_slice(hmac_key_str.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(b"dumpling-domain-map-v1");
            mac.update(spec.strategy.as_bytes());
            mac.update(domain_key.as_bytes());
            if let Some(orig) = original_unescaped {
                mac.update(orig.as_bytes());
            }
            mac.update(&collision_index.to_le_bytes());
            let seed: [u8; 32] = mac.finalize().into_bytes()[..]
                .try_into()
                .expect("HMAC-SHA-256 output is always 32 bytes");
            seed
        } else {
            let mut hasher = Sha256::new();
            hasher.update(b"dumpling-domain-map-v1");
            if let Some(salt) = spec.salt.as_ref().or(registry.default_salt.as_ref()) {
                hasher.update(salt.as_bytes());
            }
            hasher.update(spec.strategy.as_bytes());
            hasher.update(domain_key.as_bytes());
            if let Some(orig) = original_unescaped {
                hasher.update(orig.as_bytes());
            }
            hasher.update(collision_index.to_le_bytes());
            let seed: [u8; 32] = hasher.finalize()[..]
                .try_into()
                .expect("SHA-256 output is always 32 bytes");
            seed
        };
        Self {
            seed,
            counter: 0,
            block: [0u8; 32],
            block_index: 32,
            use_hmac,
        }
    }

    fn next_u8(&mut self) -> u8 {
        if self.block_index >= self.block.len() {
            self.refill();
        }
        let value = self.block[self.block_index];
        self.block_index += 1;
        value
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        for byte in &mut bytes {
            *byte = self.next_u8();
        }
        u64::from_le_bytes(bytes)
    }

    fn refill(&mut self) {
        if self.use_hmac {
            // Hardened: HMAC-SHA-256 CTR-mode expansion keyed by the seed derived from salt.
            let mut mac =
                HmacSha256::new_from_slice(&self.seed).expect("HMAC accepts any key length");
            mac.update(&self.counter.to_le_bytes());
            self.block = mac.finalize().into_bytes()[..]
                .try_into()
                .expect("HMAC-SHA-256 output is always 32 bytes");
        } else {
            let mut hasher = Sha256::new();
            hasher.update(self.seed);
            hasher.update(self.counter.to_le_bytes());
            self.block = hasher.finalize()[..]
                .try_into()
                .expect("SHA-256 output is always 32 bytes");
        }
        self.counter = self.counter.saturating_add(1);
        self.block_index = 0;
    }
}

fn deterministic_range_inclusive(min: i64, max: i64, stream: &mut DeterministicByteStream) -> i64 {
    if min >= max {
        return min;
    }
    let span = (max - min + 1) as u64;
    let v = stream.next_u64() % span;
    min + v as i64
}

fn deterministic_alnum(n: usize, stream: &mut DeterministicByteStream) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let idx = (stream.next_u64() as usize) % ALNUM.len();
        out.push(ALNUM[idx] as char);
    }
    out
}

fn random_frac_digits(scale: u32) -> String {
    let mut s = String::with_capacity(scale as usize);
    for _ in 0..scale {
        s.push(char::from(b'0' + (random_u32() % 10) as u8));
    }
    s
}

fn deterministic_frac_digits(scale: u32, stream: &mut DeterministicByteStream) -> String {
    let mut s = String::with_capacity(scale as usize);
    for _ in 0..scale {
        s.push(char::from(b'0' + (stream.next_u64() % 10) as u8));
    }
    s
}

/// `int_part` in `[min, max]`; `scale` fractional digits (0 = integer only).
fn decimal_replacement(
    min: i64,
    max: i64,
    scale: u32,
    as_string: bool,
    mut stream: Option<&mut DeterministicByteStream>,
) -> Replacement {
    let int_part = match &mut stream {
        Some(s) => deterministic_range_inclusive(min, max, s),
        None => random_range_inclusive(min, max),
    };
    if scale == 0 {
        let v = int_part.to_string();
        return if as_string {
            Replacement::quoted(v)
        } else {
            Replacement::unquoted(v)
        };
    }
    let frac = match &mut stream {
        Some(s) => deterministic_frac_digits(scale, s),
        None => random_frac_digits(scale),
    };
    let v = format!("{int_part}.{frac}");
    if as_string {
        Replacement::quoted(v)
    } else {
        Replacement::unquoted(v)
    }
}

fn luhn_check_digit_for_prefix(prefix: &[u8]) -> u8 {
    for check in 0u8..=9 {
        let mut s = String::with_capacity(prefix.len() + 1);
        for &d in prefix {
            s.push(char::from(b'0' + d));
        }
        s.push(char::from(b'0' + check));
        if luhn_valid(&s) {
            return check;
        }
    }
    0
}

fn random_payment_card_digits(len: usize) -> String {
    let mut prefix: Vec<u8> = Vec::with_capacity(len - 1);
    for i in 0..len - 1 {
        let d = if i == 0 {
            1 + (random_u32() % 9)
        } else {
            random_u32() % 10
        };
        prefix.push(d as u8);
    }
    let check = luhn_check_digit_for_prefix(&prefix);
    let mut s = String::with_capacity(len);
    for d in prefix {
        s.push(char::from(b'0' + d));
    }
    s.push(char::from(b'0' + check));
    s
}

fn deterministic_payment_card_digits(len: usize, stream: &mut DeterministicByteStream) -> String {
    let mut prefix: Vec<u8> = Vec::with_capacity(len - 1);
    for i in 0..len - 1 {
        let d = if i == 0 {
            1 + (stream.next_u64() % 9)
        } else {
            stream.next_u64() % 10
        };
        prefix.push(d as u8);
    }
    let check = luhn_check_digit_for_prefix(&prefix);
    let mut s = String::with_capacity(len);
    for d in prefix {
        s.push(char::from(b'0' + d));
    }
    s.push(char::from(b'0' + check));
    s
}

fn deterministic_uuid_v4(stream: &mut DeterministicByteStream) -> String {
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        *byte = stream.next_u8();
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    fn hex(b: u8) -> [char; 2] {
        const HEX: &[u8] = b"0123456789abcdef";
        [
            HEX[(b >> 4) as usize] as char,
            HEX[(b & 0x0F) as usize] as char,
        ]
    }
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        let h = hex(*b);
        s.push(h[0]);
        s.push(h[1]);
    }
    s
}

fn should_enforce_max_len(strategy: &str) -> bool {
    !matches!(
        strategy,
        "null" | "blank" | "empty_array" | "empty_object" | "int_range"
    )
}

fn truncate_arc_str(value: Arc<str>, max_len: usize) -> Arc<str> {
    if value.chars().count() <= max_len {
        return value;
    }
    Arc::from(value.chars().take(max_len).collect::<String>())
}

fn random_alnum(n: usize) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let idx = (random_u32() as usize) % ALNUM.len();
        out.push(ALNUM[idx] as char);
    }
    out
}

// xorshift64* PRNG seeded from system time or an explicit seed override.
fn random_u32() -> u32 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);

    // Hardened profile: use OS CSPRNG; xorshift64* is not used.
    if is_hardened_profile() {
        let mut buf = [0u8; 4];
        csprng_fill(&mut buf);
        return u32::from_le_bytes(buf);
    }

    let s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        let seed = unsafe {
            if let Some(ovr) = RNG_SEED_OVERRIDE {
                ovr
            } else {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                nanos ^ (&STATE as *const _ as u64)
            }
        };
        STATE.store(seed | 1, Ordering::Relaxed); // avoid zero state
    }
    let mut x = STATE.load(Ordering::Relaxed);
    // xorshift64*
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    STATE.store(x, Ordering::Relaxed);
    let r = x.wrapping_mul(0x2545F4914F6CDD1D_u64);
    (r >> 32) as u32
}

fn random_range_inclusive(min: i64, max: i64) -> i64 {
    if min >= max {
        return min;
    }
    let span = (max - min + 1) as u64;
    let v = (random_u32() as u64) % span;
    min + v as i64
}

fn pseudo_uuid_v4() -> String {
    // Generate 16 random bytes using random_u32
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let r = random_u32();
        bytes[i * 4] = (r >> 24) as u8;
        bytes[i * 4 + 1] = (r >> 16) as u8;
        bytes[i * 4 + 2] = (r >> 8) as u8;
        bytes[i * 4 + 3] = r as u8;
    }
    // Set version (4) and variant (10)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    // Format as 8-4-4-4-12 hex
    fn hex(b: u8) -> [char; 2] {
        const HEX: &[u8] = b"0123456789abcdef";
        [
            HEX[(b >> 4) as usize] as char,
            HEX[(b & 0x0F) as usize] as char,
        ]
    }
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        let h = hex(*b);
        s.push(h[0]);
        s.push(h[1]);
    }
    s
}

/// Allow tests/CLI to set a deterministic PRNG seed.
pub fn set_random_seed(seed: u64) {
    unsafe {
        RNG_SEED_OVERRIDE = Some(seed | 1);
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    // Reinitialize state immediately
    STATE.store(seed | 1, Ordering::Relaxed);
}

/// Active `--seed` / `DUMPLING_SEED` override for the standard profile, if any (`None` means
/// non-reproducible system-time seeding). Used for dump seal fingerprints; hardened mode ignores
/// CLI/env seeds at runtime, so this returns `None` when the hardened profile is active.
pub fn prng_seed_override_for_fingerprint() -> Option<u64> {
    if is_hardened_profile() {
        return None;
    }
    unsafe { RNG_SEED_OVERRIDE }
}

fn fuzz_date(input: &str, shift_days: i64) -> Option<String> {
    // Try parse as YYYY-MM-DD
    let trimmed = input.trim();
    if let Ok(d) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let nd = d.checked_add_signed(Duration::days(shift_days))?;
        return Some(nd.format("%Y-%m-%d").to_string());
    }
    None
}

fn fuzz_time(input: &str, shift_seconds: i64) -> Option<String> {
    let trimmed = input.trim();
    // Try with fractional then without
    let mut had_fraction = false;
    let t = if let Ok(t) = NaiveTime::parse_from_str(trimmed, "%H:%M:%S%.f") {
        had_fraction = true;
        t
    } else if let Ok(t) = NaiveTime::parse_from_str(trimmed, "%H:%M:%S") {
        t
    } else if let Ok(t) = NaiveTime::parse_from_str(trimmed, "%H:%M") {
        t
    } else {
        return None;
    };
    let secs_since_midnight = t.num_seconds_from_midnight() as i64;
    let mut total = secs_since_midnight + shift_seconds;
    // Wrap around 24h
    let day = 24 * 3600;
    total = ((total % day) + day) % day;
    let new_t = NaiveTime::from_num_seconds_from_midnight_opt(total as u32, t.nanosecond())?;
    let fmt = if had_fraction && new_t.nanosecond() > 0 {
        "%H:%M:%S%.f"
    } else if t.second() > 0 || new_t.second() > 0 {
        "%H:%M:%S"
    } else {
        "%H:%M"
    };
    Some(new_t.format(fmt).to_string())
}

fn fuzz_datetime(input: &str, shift_seconds: i64) -> Option<String> {
    let trimmed = input.trim();
    // Try parse with offset
    let fmts_with_offset = [
        "%Y-%m-%d %H:%M:%S%.f%:z",
        "%Y-%m-%d %H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
    ];
    for fmt in &fmts_with_offset {
        if let Ok(dt) = DateTime::parse_from_str(trimmed, fmt) {
            let new = dt.checked_add_signed(Duration::seconds(shift_seconds))?;
            return Some(new.format(fmt).to_string());
        }
    }
    // Parse as naive datetime (no offset)
    let fmts_naive = [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ];
    for fmt in &fmts_naive {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, fmt) {
            let new = ndt.checked_add_signed(Duration::seconds(shift_seconds))?;
            return Some(new.format(fmt).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::luhn_valid;
    use crate::settings::AnonymizerSpec;
    use std::collections::HashMap;

    fn make_spec(strategy: &str, salt: Option<&str>, domain: Option<&str>) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: salt.map(|s| s.to_string()),
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: domain.map(|d| d.to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        }
    }

    fn make_registry(salt: Option<&str>) -> AnonymizerRegistry {
        AnonymizerRegistry {
            default_salt: salt.map(|s| s.to_string()),
            security_profile: SecurityProfile::Standard,
            domain_mappings: RefCell::new(HashMap::new()),
            faker_rng: RefCell::new(make_random_rng()),
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
        }
    }

    fn make_hardened_registry(salt: Option<&str>) -> AnonymizerRegistry {
        AnonymizerRegistry {
            default_salt: salt.map(|s| s.to_string()),
            security_profile: SecurityProfile::Hardened,
            domain_mappings: RefCell::new(HashMap::new()),
            faker_rng: RefCell::new(make_random_rng()),
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
        }
    }

    // --- Hardened profile: hash strategy (random path, no domain) ---
    // These tests use the registry's security_profile field directly; no global state needed.

    #[test]
    fn test_hardened_hash_is_deterministic_for_same_input() {
        let registry = make_hardened_registry(Some("test-key"));
        let spec = make_spec("hash", None, None);
        let r1 = apply_anonymizer(&registry, &spec, Some("sensitive-value"), None);
        let r2 = apply_anonymizer(&registry, &spec, Some("sensitive-value"), None);
        assert!(!r1.is_null);
        assert_eq!(
            r1.value, r2.value,
            "HMAC hash must be deterministic for same input+key"
        );
    }

    #[test]
    fn test_hardened_hash_differs_from_standard_for_same_input() {
        let standard_registry = make_registry(Some("test-key"));
        let hardened_registry = make_hardened_registry(Some("test-key"));
        let spec = make_spec("hash", None, None);

        let standard_result =
            apply_anonymizer(&standard_registry, &spec, Some("sensitive-value"), None);
        let hardened_result =
            apply_anonymizer(&hardened_registry, &spec, Some("sensitive-value"), None);

        // HMAC-SHA-256 vs SHA-256(salt||input) produce different digests.
        assert_ne!(
            standard_result.value, hardened_result.value,
            "Hardened HMAC hash must differ from standard SHA-256 hash"
        );
    }

    #[test]
    fn test_hardened_hash_uses_key_for_separation() {
        let registry_a = make_hardened_registry(Some("key-a"));
        let registry_b = make_hardened_registry(Some("key-b"));
        let spec = make_spec("hash", None, None);
        let r_a = apply_anonymizer(&registry_a, &spec, Some("value"), None);
        let r_b = apply_anonymizer(&registry_b, &spec, Some("value"), None);
        assert_ne!(
            r_a.value, r_b.value,
            "Different HMAC keys must produce different hashes"
        );
    }

    // --- Hardened profile: domain-based deterministic path ---
    // These tests use make_hardened_registry, so there is no global state dependency.

    #[test]
    fn test_hardened_domain_hash_is_consistent() {
        let spec = make_spec("hash", None, Some("user_identity"));
        let r1 = apply_anonymizer(
            &make_hardened_registry(Some("enterprise-key")),
            &spec,
            Some("alice@corp.example"),
            None,
        );
        // Fresh registry with same key → must produce identical pseudonym.
        let r2 = apply_anonymizer(
            &make_hardened_registry(Some("enterprise-key")),
            &make_spec("hash", None, Some("user_identity")),
            Some("alice@corp.example"),
            None,
        );
        assert_eq!(
            r1.value, r2.value,
            "Hardened HMAC domain hash must be deterministic for same key+input"
        );
    }

    #[test]
    fn test_hardened_domain_email_is_consistent() {
        let spec = make_spec("email", None, Some("emails"));
        let r1 = apply_anonymizer(
            &make_hardened_registry(Some("enterprise-key")),
            &spec,
            Some("original@example.com"),
            None,
        );
        let r2 = apply_anonymizer(
            &make_hardened_registry(Some("enterprise-key")),
            &make_spec("email", None, Some("emails")),
            Some("original@example.com"),
            None,
        );
        assert!(r1.value.contains('@'), "Generated email must contain @");
        assert_eq!(
            r1.value, r2.value,
            "Hardened domain email must be deterministic"
        );
    }

    #[test]
    fn test_hardened_domain_differs_from_standard_domain() {
        let spec = make_spec("email", None, Some("emails"));
        let r_std = apply_anonymizer(
            &make_registry(Some("enterprise-key")),
            &spec,
            Some("original@example.com"),
            None,
        );
        let r_hrd = apply_anonymizer(
            &make_hardened_registry(Some("enterprise-key")),
            &make_spec("email", None, Some("emails")),
            Some("original@example.com"),
            None,
        );
        assert_ne!(
            r_std.value, r_hrd.value,
            "Hardened and standard domain paths must produce different pseudonyms"
        );
    }

    // --- Hardened profile: random strategies use CSPRNG ---
    // These tests use the global set_hardened_profile to activate CSPRNG in random_u32().
    // They only test output format / variance, not exact values, so parallel execution is safe.

    #[test]
    fn test_hardened_random_email_is_valid_format() {
        set_hardened_profile(true);
        let registry = make_hardened_registry(None);
        let spec = make_spec("email", None, None);
        let r = apply_anonymizer(&registry, &spec, Some("anything"), None);
        set_hardened_profile(false);
        assert!(r.value.contains('@'), "CSPRNG-backed email must contain @");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_hardened_random_uuid_is_valid_format() {
        set_hardened_profile(true);
        let registry = make_hardened_registry(None);
        let spec = make_spec("uuid", None, None);
        let r = apply_anonymizer(&registry, &spec, None, None);
        set_hardened_profile(false);
        let parts: Vec<&str> = r.value.split('-').collect();
        assert_eq!(parts.len(), 5, "UUID must have 5 hyphen-separated segments");
        assert_eq!(
            parts[2].chars().next(),
            Some('4'),
            "UUID version nibble must be 4"
        );
    }

    #[test]
    fn test_blank_empty_array_empty_object_strategies() {
        let registry = make_registry(None);
        let blank = make_spec("blank", None, None);
        assert!(apply_anonymizer(&registry, &blank, None, None).is_null);
        let b = apply_anonymizer(&registry, &blank, Some("x"), None);
        assert!(!b.is_null);
        assert!(b.force_quoted);
        assert!(b.value.is_empty());

        let ea = make_spec("empty_array", None, None);
        assert!(apply_anonymizer(&registry, &ea, None, None).is_null);
        let a = apply_anonymizer(&registry, &ea, Some("[1]"), None);
        assert_eq!(a.value.as_ref(), "[]");
        assert!(!a.force_quoted);

        let eo = make_spec("empty_object", None, None);
        assert!(apply_anonymizer(&registry, &eo, None, None).is_null);
        let o = apply_anonymizer(&registry, &eo, Some(r#"{"a":1}"#), None);
        assert_eq!(o.value.as_ref(), "{}");
        assert!(!o.force_quoted);
    }

    #[test]
    fn test_hardened_random_values_are_non_deterministic() {
        // Confirm CSPRNG produces varying values (extremely unlikely to collide).
        set_hardened_profile(true);
        let registry = make_hardened_registry(None);
        let spec = make_spec("string", None, None);
        let r1 = apply_anonymizer(&registry, &spec, None, None);
        let r2 = apply_anonymizer(&registry, &spec, None, None);
        set_hardened_profile(false);
        // With 12 random alnum chars, collision probability is negligible.
        assert_ne!(
            r1.value, r2.value,
            "Consecutive CSPRNG string calls must almost certainly differ"
        );
    }

    #[test]
    fn test_decimal_random_respects_min_max_and_scale() {
        set_random_seed(99_001);
        let registry = make_registry(None);
        let spec = AnonymizerSpec {
            strategy: "decimal".to_string(),
            salt: None,
            min: Some(10),
            max: Some(20),
            scale: Some(3),
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let r = apply_anonymizer(&registry, &spec, Some("99.99"), None);
        let (whole, frac) = r.value.split_once('.').expect("decimal must contain a dot");
        let int_part: i64 = whole.parse().expect("integer part must parse");
        assert!((10..=20).contains(&int_part));
        assert_eq!(frac.len(), 3);
        assert!(frac.chars().all(|c| c.is_ascii_digit()));
        assert!(!r.force_quoted);
    }

    #[test]
    fn test_decimal_domain_maps_consistently() {
        let registry = make_registry(None);
        let spec = AnonymizerSpec {
            strategy: "decimal".to_string(),
            salt: None,
            min: Some(0),
            max: Some(5),
            scale: Some(2),
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("amounts".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let a = apply_anonymizer(&registry, &spec, Some("100.50"), None);
        let b = apply_anonymizer(&registry, &spec, Some("100.50"), None);
        assert_eq!(a.value, b.value);
    }

    #[test]
    fn test_payment_card_random_is_luhn_valid() {
        set_random_seed(42_424);
        let registry = make_registry(None);
        let spec = AnonymizerSpec {
            strategy: "payment_card".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: Some(16),
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let r = apply_anonymizer(&registry, &spec, Some("4111111111111111"), None);
        assert!(r.force_quoted);
        assert_eq!(r.value.len(), 16);
        assert!(r.value.chars().all(|c| c.is_ascii_digit()));
        assert!(luhn_valid(&r.value), "PAN must pass Luhn: {}", r.value);
    }

    #[test]
    fn test_payment_card_domain_deterministic() {
        let registry = make_registry(None);
        let spec = AnonymizerSpec {
            strategy: "payment_card".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: Some(16),
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("cards".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let r1 = apply_anonymizer(&registry, &spec, Some("4111111111111111"), None);
        let r2 = apply_anonymizer(&registry, &spec, Some("4111111111111111"), None);
        assert_eq!(r1.value, r2.value);
        assert!(luhn_valid(&r1.value));
    }

    // --- Localized name and phone strategies ---

    fn make_spec_with_locale(strategy: &str, locale: Option<&str>) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: locale.map(|l| l.to_string()),
            faker: None,
            format: None,
        }
    }

    #[test]
    fn test_name_default_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("name", None);
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "default-locale name must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_name_en_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("name", Some("en"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty());
        assert!(r.force_quoted);
    }

    #[test]
    fn test_name_de_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("name", Some("de_de"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "German-locale name must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_first_name_fr_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("first_name", Some("fr_fr"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "French first_name must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_last_name_zh_cn_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("last_name", Some("zh_cn"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "Chinese last_name must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_phone_en_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("phone", Some("en"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "EN phone must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_phone_de_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("phone", Some("de_de"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "German phone must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_phone_ja_locale_produces_non_empty_string() {
        let registry = make_registry(None);
        let spec = make_spec_with_locale("phone", Some("ja_jp"));
        let r = apply_anonymizer(&registry, &spec, None, None);
        assert!(!r.is_null);
        assert!(!r.value.is_empty(), "Japanese phone must be non-empty");
        assert!(r.force_quoted);
    }

    #[test]
    fn test_localized_name_domain_deterministic() {
        // Same original value + domain + locale must always produce the same pseudonym.
        let spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("user_names".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: Some("fr_fr".to_string()),
            faker: Some("name::Name".to_string()),
            format: None,
        };
        let r1 = apply_anonymizer(&make_registry(None), &spec, Some("Original Name"), None);
        let r2 = apply_anonymizer(
            &make_registry(None),
            &AnonymizerSpec {
                strategy: "faker".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("user_names".to_string()),
                unique_within_domain: None,
                as_string: None,
                locale: Some("fr_fr".to_string()),
                faker: Some("name::Name".to_string()),
                format: None,
            },
            Some("Original Name"),
            None,
        );
        assert_eq!(
            r1.value, r2.value,
            "Localized domain-mapped name must be deterministic"
        );
    }

    #[test]
    fn test_localized_phone_domain_deterministic() {
        let spec = AnonymizerSpec {
            strategy: "phone".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("phones".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: Some("de_de".to_string()),
            faker: None,
            format: None,
        };
        let r1 = apply_anonymizer(&make_registry(None), &spec, Some("+49 30 12345678"), None);
        let r2 = apply_anonymizer(
            &make_registry(None),
            &AnonymizerSpec {
                strategy: "phone".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("phones".to_string()),
                unique_within_domain: None,
                as_string: None,
                locale: Some("de_de".to_string()),
                faker: None,
                format: None,
            },
            Some("+49 30 12345678"),
            None,
        );
        assert_eq!(
            r1.value, r2.value,
            "Localized domain-mapped phone must be deterministic"
        );
    }

    // --- NULL value preservation in domain mapping ---

    #[test]
    fn test_domain_mapping_preserves_null_input() {
        // A NULL input to a domain-mapped column must remain NULL, not be replaced
        // with a random or deterministic pseudonym. NULL typically means "no FK reference"
        // and fabricating a value would break referential integrity.
        let registry = make_registry(None);
        let spec = make_spec("email", None, Some("customer_identity"));
        let result = apply_anonymizer(&registry, &spec, None, None);
        assert!(
            result.is_null,
            "domain-mapped email with NULL input must produce NULL, not '{}'",
            result.value
        );
    }

    #[test]
    fn test_domain_mapping_preserves_null_while_non_null_maps_consistently() {
        // NULL inputs → NULL; non-NULL inputs → stable deterministic pseudonym.
        // Using the same registry ensures both share domain state.
        let registry = make_registry(None);
        let spec = make_spec("email", None, Some("customer_identity"));

        let null_result = apply_anonymizer(&registry, &spec, None, None);
        let non_null_result1 = apply_anonymizer(&registry, &spec, Some("alice@corp.com"), None);
        let non_null_result2 = apply_anonymizer(&registry, &spec, Some("alice@corp.com"), None);

        assert!(null_result.is_null, "NULL input must produce NULL");
        assert!(
            !non_null_result1.is_null,
            "non-NULL input must not produce NULL"
        );
        assert_eq!(
            non_null_result1.value, non_null_result2.value,
            "same source value must map to same pseudonym"
        );
    }

    #[test]
    fn test_domain_mapping_null_does_not_pollute_domain_state() {
        // A NULL input must not be entered into the forward/reverse domain mapping cache.
        // Subsequent non-NULL inputs should still map deterministically to their own pseudonyms.
        let registry = make_registry(None);
        let spec = make_spec("email", None, Some("customer_identity"));

        // First call: NULL input
        let null_result = apply_anonymizer(&registry, &spec, None, None);
        assert!(null_result.is_null, "NULL input must produce NULL");

        // Second call: non-NULL input — should produce a real deterministic pseudonym
        let non_null_result = apply_anonymizer(&registry, &spec, Some("bob@corp.com"), None);
        assert!(
            !non_null_result.is_null,
            "non-NULL input after NULL must still produce a real value"
        );
        assert!(
            non_null_result.value.contains('@'),
            "email pseudonym must contain '@'"
        );

        // Third call: same non-NULL input — must produce identical pseudonym
        let repeat_result = apply_anonymizer(&registry, &spec, Some("bob@corp.com"), None);
        assert_eq!(
            non_null_result.value, repeat_result.value,
            "repeated non-NULL input must produce identical pseudonym"
        );
    }

    #[test]
    fn test_domain_mapping_null_preserved_with_unique_within_domain() {
        // unique_within_domain=true must not affect NULL: NULL stays NULL.
        let registry = make_registry(None);
        let spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("customer_identity".to_string()),
            unique_within_domain: Some(true),
            as_string: None,
            locale: None,
            faker: Some("internet::SafeEmail".to_string()),
            format: None,
        };
        let result = apply_anonymizer(&registry, &spec, None, None);
        assert!(
            result.is_null,
            "NULL input with unique_within_domain=true must still produce NULL"
        );
    }

    #[test]
    fn test_domain_mapping_null_preserved_for_multiple_strategies() {
        // Verify NULL preservation works across all strategies that support domain mapping.
        let registry = make_registry(None);
        for strategy in &[
            "email",
            "uuid",
            "name",
            "first_name",
            "last_name",
            "string",
            "decimal",
            "payment_card",
        ] {
            let spec = make_spec(strategy, None, Some("test_domain"));
            let result = apply_anonymizer(&registry, &spec, None, None);
            assert!(
                result.is_null,
                "domain-mapped strategy '{}' with NULL input must produce NULL",
                strategy
            );
        }
    }
}
