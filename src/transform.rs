use crate::settings::{AnonymizerSpec, ResolvedConfig};
use chrono::Timelike;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

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
        }
    }
}

#[derive(Clone, Debug)]
pub struct Replacement {
    /// The replacement value without surrounding SQL quotes
    pub value: String,
    /// If true, force render as quoted literal
    pub force_quoted: bool,
    /// If true, render as NULL
    pub is_null: bool,
}

impl Replacement {
    pub fn null() -> Self {
        Self {
            value: String::new(),
            force_quoted: false,
            is_null: true,
        }
    }
    pub fn quoted<V: Into<String>>(v: V) -> Self {
        Self {
            value: v.into(),
            force_quoted: true,
            is_null: false,
        }
    }
    pub fn unquoted<V: Into<String>>(v: V) -> Self {
        Self {
            value: v.into(),
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
            replacement.value = truncate_to_max_chars(&replacement.value, max_len);
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
        // Keep legacy behavior for NULL / missing original values.
        return apply_random_anonymizer(registry, spec, original_unescaped);
    };

    let mut mappings = registry.domain_mappings.borrow_mut();
    let mapping = mappings.entry(domain_key.to_string()).or_default();
    if let Some(existing) = mapping.forward.get(original_value) {
        return existing.clone();
    }

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
        replacement.value.clone()
    }
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
        "email" => {
            let user: String = random_alnum(10).to_lowercase();
            let domain = "example.com";
            let email = format!("{}@{}", user, domain);
            Replacement::quoted(email)
        }
        "name" => {
            // Using fake crate can be heavy; generate simple placeholder
            // Keep to ascii and space-safe
            let first = random_alpha_lower(6);
            let last = random_alpha_lower(8);
            Replacement::quoted(format!(
                "{} {}",
                capitalize_first(&first),
                capitalize_first(&last)
            ))
        }
        "first_name" => {
            let first = random_alpha_lower(6);
            Replacement::quoted(capitalize_first(&first))
        }
        "last_name" => {
            let last = random_alpha_lower(8);
            Replacement::quoted(capitalize_first(&last))
        }
        "phone" => {
            let digits: String = (0..10).map(|_| (random_u32() % 10).to_string()).collect();
            let phone = format!("({}) {}-{}", &digits[0..3], &digits[3..6], &digits[6..10]);
            Replacement::quoted(phone)
        }
        "int_range" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let v = random_range_inclusive(min, max);
            Replacement::unquoted(v.to_string())
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
                } else {
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
                } else {
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
        "email" => {
            let user = deterministic_alnum(10, &mut stream).to_lowercase();
            Replacement::quoted(format!("{}@example.com", user))
        }
        "name" => {
            let first = deterministic_alpha_lower(6, &mut stream);
            let last = deterministic_alpha_lower(8, &mut stream);
            Replacement::quoted(format!(
                "{} {}",
                capitalize_first(&first),
                capitalize_first(&last)
            ))
        }
        "first_name" => {
            let first = deterministic_alpha_lower(6, &mut stream);
            Replacement::quoted(capitalize_first(&first))
        }
        "last_name" => {
            let last = deterministic_alpha_lower(8, &mut stream);
            Replacement::quoted(capitalize_first(&last))
        }
        "phone" => {
            let digits: String = (0..10)
                .map(|_| ((stream.next_u64() % 10) as u8 + b'0') as char)
                .collect();
            Replacement::quoted(format!(
                "({}) {}-{}",
                &digits[0..3],
                &digits[3..6],
                &digits[6..10]
            ))
        }
        "int_range" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            let v = deterministic_range_inclusive(min, max, &mut stream);
            Replacement::unquoted(v.to_string())
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
            let result = mac.finalize().into_bytes();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&result[..]);
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
            let digest = hasher.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&digest[..]);
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
            // Hardened: HMAC-SHA-256 CTR-mode expansion.
            let mut mac =
                HmacSha256::new_from_slice(&self.seed).expect("HMAC accepts any key length");
            mac.update(&self.counter.to_le_bytes());
            let result = mac.finalize().into_bytes();
            self.block.copy_from_slice(&result[..]);
        } else {
            let mut hasher = Sha256::new();
            hasher.update(self.seed);
            hasher.update(self.counter.to_le_bytes());
            let digest = hasher.finalize();
            self.block.copy_from_slice(&digest[..]);
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

fn deterministic_alpha_lower(n: usize, stream: &mut DeterministicByteStream) -> String {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let idx = (stream.next_u64() as usize) % letters.len();
        out.push(letters[idx] as char);
    }
    out
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
    !matches!(strategy, "null" | "int_range")
}

fn truncate_to_max_chars(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    value.chars().take(max_len).collect()
}

fn random_alpha_lower(n: usize) -> String {
    let letters = b"abcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let idx = (random_u32() as usize) % letters.len();
        out.push(letters[idx] as char);
    }
    out
}

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
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
        bytes[i * 4 + 0] = (r >> 24) as u8;
        bytes[i * 4 + 1] = (r >> 16) as u8;
        bytes[i * 4 + 2] = (r >> 8) as u8;
        bytes[i * 4 + 3] = (r >> 0) as u8;
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
    use crate::settings::AnonymizerSpec;
    use std::collections::HashMap;

    fn make_spec(strategy: &str, salt: Option<&str>, domain: Option<&str>) -> AnonymizerSpec {
        AnonymizerSpec {
            strategy: strategy.to_string(),
            salt: salt.map(|s| s.to_string()),
            min: None,
            max: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: domain.map(|d| d.to_string()),
            unique_within_domain: None,
            as_string: None,
        }
    }

    fn make_registry(salt: Option<&str>) -> AnonymizerRegistry {
        AnonymizerRegistry {
            default_salt: salt.map(|s| s.to_string()),
            security_profile: SecurityProfile::Standard,
            domain_mappings: RefCell::new(HashMap::new()),
        }
    }

    fn make_hardened_registry(salt: Option<&str>) -> AnonymizerRegistry {
        AnonymizerRegistry {
            default_salt: salt.map(|s| s.to_string()),
            security_profile: SecurityProfile::Hardened,
            domain_mappings: RefCell::new(HashMap::new()),
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
}
