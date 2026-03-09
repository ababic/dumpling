use crate::settings::{AnonymizerSpec, ResolvedConfig};
use chrono::Timelike;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime};
use sha2::{Digest, Sha256};

pub struct AnonymizerRegistry {
    pub default_salt: Option<String>,
}

static mut RNG_SEED_OVERRIDE: Option<u64> = None;

impl AnonymizerRegistry {
    pub fn from_config(cfg: &ResolvedConfig) -> Self {
        Self {
            default_salt: cfg.salt.clone(),
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
            let mut hasher = Sha256::new();
            if let Some(salt) = spec.salt.as_ref().or(registry.default_salt.as_ref()) {
                hasher.update(salt.as_bytes());
            }
            if let Some(orig) = original_unescaped {
                hasher.update(orig.as_bytes());
            }
            let digest = hasher.finalize();
            let hex = format!("{:x}", digest);
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
        other => {
            // Unknown strategy: fall back to redact
            eprintln!("dumpling: unknown strategy '{}', using 'redact'", other);
            if as_string {
                Replacement::quoted("REDACTED")
            } else {
                Replacement::unquoted("REDACTED")
            }
        }
    }
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

// Very simple xorshift32 PRNG seeded from a time-based seed
fn random_u32() -> u32 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
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
