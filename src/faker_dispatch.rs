//! Dispatch from config `faker = "module::Type"` to the [`fake`](https://crates.io/crates/fake) crate.
//!
//! **Upstream documentation** (for humans/agents choosing or adding generators):
//! - [docs.rs — `fake` crate](https://docs.rs/fake/latest/fake/)
//! - [docs.rs — `fake::faker` modules](https://docs.rs/fake/latest/fake/faker/index.html)
//! - [GitHub — cksac/fake-rs](https://github.com/cksac/fake-rs)
//!
//! Rust cannot load arbitrary Faker types by string at runtime; this module is the **only**
//! allowlist of generators compiled into Dumpling. Config never supplies executable code—only
//! string keys that map to these arms.

use crate::settings::AnonymizerSpec;
use fake::faker::address::raw::{
    BuildingNumber, CityName, CityPrefix, CitySuffix, CountryCode, CountryName, Geohash, Latitude,
    Longitude, PostCode, SecondaryAddress, SecondaryAddressType, StateAbbr, StateName, StreetName,
    StreetSuffix, TimeZone, ZipCode,
};
use fake::faker::barcode::raw::{Isbn, Isbn10, Isbn13};
use fake::faker::boolean::raw::Boolean;
use fake::faker::company::raw::{
    Bs, BsAdj, BsNoun, BsVerb, Buzzword, BuzzwordMiddle, BuzzwordTail, CatchPhrase, CompanyName,
    CompanySuffix, Industry, Profession,
};
use fake::faker::creditcard::raw::CreditCardNumber;
use fake::faker::currency::raw::{CurrencyCode, CurrencyName, CurrencySymbol};
use fake::faker::filesystem::raw::{
    DirPath, FileExtension, FileName, FilePath, MimeType, Semver, SemverStable, SemverUnstable,
};
use fake::faker::finance::raw::{Bic, Isin};
use fake::faker::internet::raw::{
    DomainSuffix, FreeEmail, FreeEmailProvider, IPv4, IPv6, MACAddress, Password, SafeEmail,
    UserAgent, Username, IP,
};
use fake::faker::job::raw::{Field, Position, Seniority, Title as JobTitle};
use fake::faker::lorem::raw::{Paragraph, Paragraphs, Sentence, Sentences, Word, Words};
use fake::faker::markdown::raw::{
    BlockQuoteMultiLine, BlockQuoteSingleLine, BoldWord, BulletPoints, Code, ItalicWord, Link,
    ListItems,
};
use fake::faker::name::raw::{FirstName, LastName, Name, NameWithTitle, Suffix, Title};
use fake::faker::number::raw::{Digit, NumberWithFormat};
use fake::faker::phone_number::raw::{CellNumber, PhoneNumber};
use fake::locales::{AR_SA, CY_GB, DE_DE, EN, FR_FR, IT_IT, JA_JP, PT_BR, PT_PT, ZH_CN, ZH_TW};
use fake::Fake;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::ops::Range;

macro_rules! fl {
    ($locale:expr, $rng:expr, $ctor:ident) => {
        match $locale {
            "fr_fr" => $ctor(FR_FR).fake_with_rng($rng),
            "de_de" => $ctor(DE_DE).fake_with_rng($rng),
            "it_it" => $ctor(IT_IT).fake_with_rng($rng),
            "pt_br" => $ctor(PT_BR).fake_with_rng($rng),
            "pt_pt" => $ctor(PT_PT).fake_with_rng($rng),
            "ar_sa" => $ctor(AR_SA).fake_with_rng($rng),
            "zh_cn" => $ctor(ZH_CN).fake_with_rng($rng),
            "zh_tw" => $ctor(ZH_TW).fake_with_rng($rng),
            "ja_jp" => $ctor(JA_JP).fake_with_rng($rng),
            "cy_gb" => $ctor(CY_GB).fake_with_rng($rng),
            _ => $ctor(EN).fake_with_rng($rng),
        }
    };
}

/// Inclusive `min`/`max` from config → half-open `Range<usize>` for `fake` tuple fakers.
fn count_range(spec: &AnonymizerSpec, default_low: i64, default_high: i64) -> Range<usize> {
    let low = spec.min.unwrap_or(default_low).max(0) as usize;
    let high = spec.max.unwrap_or(default_high).max(0) as usize;
    let (a, b) = if low <= high {
        (low, high)
    } else {
        (high, low)
    };
    let end = b.saturating_add(1).max(a.saturating_add(1));
    a..end
}

/// Parse `faker` value: `"module::Type"` (case-insensitive module and type names).
pub fn parse_faker_path(faker: &str) -> Option<(&str, &str)> {
    let trimmed = faker.trim();
    let (module, typ) = trimmed.rsplit_once("::")?;
    let module = module.trim();
    let typ = typ.trim();
    if module.is_empty() || typ.is_empty() {
        return None;
    }
    Some((module, typ))
}

/// Normalized locale key for `faker`, `phone`, and built-in PII strategies (`email`, `name`, …).
/// Uses ASCII case-insensitive matching without allocating.
pub fn resolved_locale_key(spec: &AnonymizerSpec) -> &'static str {
    let s = spec.locale.as_deref().map(str::trim).unwrap_or("");
    if s.is_empty() || s.eq_ignore_ascii_case("en") {
        return "en";
    }
    if s.eq_ignore_ascii_case("fr_fr") {
        return "fr_fr";
    }
    if s.eq_ignore_ascii_case("de_de") {
        return "de_de";
    }
    if s.eq_ignore_ascii_case("it_it") {
        return "it_it";
    }
    if s.eq_ignore_ascii_case("pt_br") {
        return "pt_br";
    }
    if s.eq_ignore_ascii_case("pt_pt") {
        return "pt_pt";
    }
    if s.eq_ignore_ascii_case("ar_sa") {
        return "ar_sa";
    }
    if s.eq_ignore_ascii_case("zh_cn") {
        return "zh_cn";
    }
    if s.eq_ignore_ascii_case("zh_tw") {
        return "zh_tw";
    }
    if s.eq_ignore_ascii_case("ja_jp") {
        return "ja_jp";
    }
    if s.eq_ignore_ascii_case("cy_gb") {
        return "cy_gb";
    }
    "en"
}

/// Built-in `strategy = "email"` — same generator as `faker = "internet::SafeEmail"`.
pub fn pii_safe_email(loc: &str, rng: &mut StdRng) -> String {
    fl!(loc, rng, SafeEmail)
}

/// Built-in `strategy = "name"` — full name.
pub fn pii_full_name(loc: &str, rng: &mut StdRng) -> String {
    fl!(loc, rng, Name)
}

/// Built-in `strategy = "first_name"`.
pub fn pii_first_name(loc: &str, rng: &mut StdRng) -> String {
    fl!(loc, rng, FirstName)
}

/// Built-in `strategy = "last_name"`.
pub fn pii_last_name(loc: &str, rng: &mut StdRng) -> String {
    fl!(loc, rng, LastName)
}

/// Built-in `strategy = "phone"` — same generator as `faker` phone_number fakers.
pub fn pii_phone_number(loc: &str, rng: &mut StdRng) -> String {
    fl!(loc, rng, PhoneNumber)
}

pub fn faker_string_with_rng(spec: &AnonymizerSpec, rng: &mut StdRng) -> Option<String> {
    let faker = spec.faker.as_deref()?.trim();
    if faker.is_empty() {
        return None;
    }
    let (module, typ) = parse_faker_path(faker)?;
    let module_lc = module.to_ascii_lowercase();
    let typ_lc = typ.to_ascii_lowercase();
    let loc = resolved_locale_key(spec);

    let s: String = match (module_lc.as_str(), typ_lc.as_str()) {
        ("name", "firstname") => fl!(loc, rng, FirstName),
        ("name", "lastname") => fl!(loc, rng, LastName),
        ("name", "name") => fl!(loc, rng, Name),
        ("name", "namewithtitle") => fl!(loc, rng, NameWithTitle),
        ("name", "title") => fl!(loc, rng, Title),
        ("name", "suffix") => fl!(loc, rng, Suffix),

        ("internet", "freeemail") => fl!(loc, rng, FreeEmail),
        ("internet", "safeemail") => fl!(loc, rng, SafeEmail),
        ("internet", "username") => fl!(loc, rng, Username),
        ("internet", "freeemailprovider") => fl!(loc, rng, FreeEmailProvider),
        ("internet", "domainsuffix") => fl!(loc, rng, DomainSuffix),
        ("internet", "ipv4") => fl!(loc, rng, IPv4),
        ("internet", "ipv6") => fl!(loc, rng, IPv6),
        ("internet", "ip") => fl!(loc, rng, IP),
        ("internet", "macaddress") => fl!(loc, rng, MACAddress),
        ("internet", "useragent") => fl!(loc, rng, UserAgent),
        ("internet", "password") => {
            let len = spec.length.unwrap_or(12).max(1);
            let r = len..len.saturating_add(1);
            match loc {
                "fr_fr" => Password(FR_FR, r).fake_with_rng(rng),
                "de_de" => Password(DE_DE, r).fake_with_rng(rng),
                "it_it" => Password(IT_IT, r).fake_with_rng(rng),
                "pt_br" => Password(PT_BR, r).fake_with_rng(rng),
                "pt_pt" => Password(PT_PT, r).fake_with_rng(rng),
                "ar_sa" => Password(AR_SA, r).fake_with_rng(rng),
                "zh_cn" => Password(ZH_CN, r).fake_with_rng(rng),
                "zh_tw" => Password(ZH_TW, r).fake_with_rng(rng),
                "ja_jp" => Password(JA_JP, r).fake_with_rng(rng),
                "cy_gb" => Password(CY_GB, r).fake_with_rng(rng),
                _ => Password(EN, r).fake_with_rng(rng),
            }
        }

        ("phone_number", "phonenumber") | ("phone_number", "phone") => fl!(loc, rng, PhoneNumber),
        ("phone_number", "cellnumber") | ("phone_number", "cell") => fl!(loc, rng, CellNumber),

        ("address", "cityprefix") => fl!(loc, rng, CityPrefix),
        ("address", "citysuffix") => fl!(loc, rng, CitySuffix),
        ("address", "cityname") => fl!(loc, rng, CityName),
        ("address", "countryname") => fl!(loc, rng, CountryName),
        ("address", "countrycode") => fl!(loc, rng, CountryCode),
        ("address", "streetsuffix") => fl!(loc, rng, StreetSuffix),
        ("address", "streetname") => fl!(loc, rng, StreetName),
        ("address", "timezone") => fl!(loc, rng, TimeZone),
        ("address", "statename") => fl!(loc, rng, StateName),
        ("address", "stateabbr") => fl!(loc, rng, StateAbbr),
        ("address", "secondaryaddresstype") => fl!(loc, rng, SecondaryAddressType),
        ("address", "secondaryaddress") => fl!(loc, rng, SecondaryAddress),
        ("address", "zipcode") => fl!(loc, rng, ZipCode),
        ("address", "postcode") => fl!(loc, rng, PostCode),
        ("address", "buildingnumber") => fl!(loc, rng, BuildingNumber),
        ("address", "latitude") => fl!(loc, rng, Latitude),
        ("address", "longitude") => fl!(loc, rng, Longitude),
        ("address", "geohash") => {
            let p = spec.min.unwrap_or(8).clamp(1, 20) as u8;
            match loc {
                "fr_fr" => Geohash(FR_FR, p).fake_with_rng(rng),
                "de_de" => Geohash(DE_DE, p).fake_with_rng(rng),
                "it_it" => Geohash(IT_IT, p).fake_with_rng(rng),
                "pt_br" => Geohash(PT_BR, p).fake_with_rng(rng),
                "pt_pt" => Geohash(PT_PT, p).fake_with_rng(rng),
                "ar_sa" => Geohash(AR_SA, p).fake_with_rng(rng),
                "zh_cn" => Geohash(ZH_CN, p).fake_with_rng(rng),
                "zh_tw" => Geohash(ZH_TW, p).fake_with_rng(rng),
                "ja_jp" => Geohash(JA_JP, p).fake_with_rng(rng),
                "cy_gb" => Geohash(CY_GB, p).fake_with_rng(rng),
                _ => Geohash(EN, p).fake_with_rng(rng),
            }
        }

        ("company", "companysuffix") => fl!(loc, rng, CompanySuffix),
        ("company", "companyname") => fl!(loc, rng, CompanyName),
        ("company", "buzzword") => fl!(loc, rng, Buzzword),
        ("company", "buzzwordmiddle") => fl!(loc, rng, BuzzwordMiddle),
        ("company", "buzzwordtail") => fl!(loc, rng, BuzzwordTail),
        ("company", "catchphrase") => fl!(loc, rng, CatchPhrase),
        ("company", "bsverb") => fl!(loc, rng, BsVerb),
        ("company", "bsadj") => fl!(loc, rng, BsAdj),
        ("company", "bsnoun") => fl!(loc, rng, BsNoun),
        ("company", "bs") => fl!(loc, rng, Bs),
        ("company", "profession") => fl!(loc, rng, Profession),
        ("company", "industry") => fl!(loc, rng, Industry),

        ("job", "seniority") => fl!(loc, rng, Seniority),
        ("job", "field") => fl!(loc, rng, Field),
        ("job", "position") => fl!(loc, rng, Position),
        ("job", "title") => fl!(loc, rng, JobTitle),

        ("lorem", "word") => fl!(loc, rng, Word),
        ("lorem", "words") => {
            let r = count_range(spec, 3, 5);
            match loc {
                "fr_fr" => Words(FR_FR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "de_de" => Words(DE_DE, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "it_it" => Words(IT_IT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "pt_br" => Words(PT_BR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "pt_pt" => Words(PT_PT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "ar_sa" => Words(AR_SA, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "zh_cn" => Words(ZH_CN, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "zh_tw" => Words(ZH_TW, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "ja_jp" => Words(JA_JP, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                "cy_gb" => Words(CY_GB, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join(" "),
                _ => Words(EN, r).fake_with_rng::<Vec<String>, _>(rng).join(" "),
            }
        }
        ("lorem", "sentence") => {
            let r = count_range(spec, 4, 10);
            match loc {
                "fr_fr" => Sentence(FR_FR, r).fake_with_rng(rng),
                "de_de" => Sentence(DE_DE, r).fake_with_rng(rng),
                "it_it" => Sentence(IT_IT, r).fake_with_rng(rng),
                "pt_br" => Sentence(PT_BR, r).fake_with_rng(rng),
                "pt_pt" => Sentence(PT_PT, r).fake_with_rng(rng),
                "ar_sa" => Sentence(AR_SA, r).fake_with_rng(rng),
                "zh_cn" => Sentence(ZH_CN, r).fake_with_rng(rng),
                "zh_tw" => Sentence(ZH_TW, r).fake_with_rng(rng),
                "ja_jp" => Sentence(JA_JP, r).fake_with_rng(rng),
                "cy_gb" => Sentence(CY_GB, r).fake_with_rng(rng),
                _ => Sentence(EN, r).fake_with_rng(rng),
            }
        }
        ("lorem", "sentences") => {
            let outer = count_range(spec, 2, 4);
            let v: Vec<String> = match loc {
                "fr_fr" => Sentences(FR_FR, outer).fake_with_rng(rng),
                "de_de" => Sentences(DE_DE, outer).fake_with_rng(rng),
                "it_it" => Sentences(IT_IT, outer).fake_with_rng(rng),
                "pt_br" => Sentences(PT_BR, outer).fake_with_rng(rng),
                "pt_pt" => Sentences(PT_PT, outer).fake_with_rng(rng),
                "ar_sa" => Sentences(AR_SA, outer).fake_with_rng(rng),
                "zh_cn" => Sentences(ZH_CN, outer).fake_with_rng(rng),
                "zh_tw" => Sentences(ZH_TW, outer).fake_with_rng(rng),
                "ja_jp" => Sentences(JA_JP, outer).fake_with_rng(rng),
                "cy_gb" => Sentences(CY_GB, outer).fake_with_rng(rng),
                _ => Sentences(EN, outer).fake_with_rng(rng),
            };
            v.join(" ")
        }
        ("lorem", "paragraph") => {
            let r = count_range(spec, 4, 7);
            match loc {
                "fr_fr" => Paragraph(FR_FR, r).fake_with_rng(rng),
                "de_de" => Paragraph(DE_DE, r).fake_with_rng(rng),
                "it_it" => Paragraph(IT_IT, r).fake_with_rng(rng),
                "pt_br" => Paragraph(PT_BR, r).fake_with_rng(rng),
                "pt_pt" => Paragraph(PT_PT, r).fake_with_rng(rng),
                "ar_sa" => Paragraph(AR_SA, r).fake_with_rng(rng),
                "zh_cn" => Paragraph(ZH_CN, r).fake_with_rng(rng),
                "zh_tw" => Paragraph(ZH_TW, r).fake_with_rng(rng),
                "ja_jp" => Paragraph(JA_JP, r).fake_with_rng(rng),
                "cy_gb" => Paragraph(CY_GB, r).fake_with_rng(rng),
                _ => Paragraph(EN, r).fake_with_rng(rng),
            }
        }
        ("lorem", "paragraphs") => {
            let outer = count_range(spec, 2, 4);
            let v: Vec<String> = match loc {
                "fr_fr" => Paragraphs(FR_FR, outer).fake_with_rng(rng),
                "de_de" => Paragraphs(DE_DE, outer).fake_with_rng(rng),
                "it_it" => Paragraphs(IT_IT, outer).fake_with_rng(rng),
                "pt_br" => Paragraphs(PT_BR, outer).fake_with_rng(rng),
                "pt_pt" => Paragraphs(PT_PT, outer).fake_with_rng(rng),
                "ar_sa" => Paragraphs(AR_SA, outer).fake_with_rng(rng),
                "zh_cn" => Paragraphs(ZH_CN, outer).fake_with_rng(rng),
                "zh_tw" => Paragraphs(ZH_TW, outer).fake_with_rng(rng),
                "ja_jp" => Paragraphs(JA_JP, outer).fake_with_rng(rng),
                "cy_gb" => Paragraphs(CY_GB, outer).fake_with_rng(rng),
                _ => Paragraphs(EN, outer).fake_with_rng(rng),
            };
            v.join("\n\n")
        }

        ("markdown", "italicword") => fl!(loc, rng, ItalicWord),
        ("markdown", "boldword") => fl!(loc, rng, BoldWord),
        ("markdown", "link") => fl!(loc, rng, Link),
        ("markdown", "bulletpoints") => {
            let r = count_range(spec, 2, 5);
            match loc {
                "fr_fr" => BulletPoints(FR_FR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "de_de" => BulletPoints(DE_DE, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "it_it" => BulletPoints(IT_IT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "pt_br" => BulletPoints(PT_BR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "pt_pt" => BulletPoints(PT_PT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "ar_sa" => BulletPoints(AR_SA, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "zh_cn" => BulletPoints(ZH_CN, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "zh_tw" => BulletPoints(ZH_TW, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "ja_jp" => BulletPoints(JA_JP, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "cy_gb" => BulletPoints(CY_GB, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                _ => BulletPoints(EN, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
            }
        }
        ("markdown", "listitems") => {
            let r = count_range(spec, 2, 5);
            match loc {
                "fr_fr" => ListItems(FR_FR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "de_de" => ListItems(DE_DE, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "it_it" => ListItems(IT_IT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "pt_br" => ListItems(PT_BR, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "pt_pt" => ListItems(PT_PT, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "ar_sa" => ListItems(AR_SA, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "zh_cn" => ListItems(ZH_CN, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "zh_tw" => ListItems(ZH_TW, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "ja_jp" => ListItems(JA_JP, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                "cy_gb" => ListItems(CY_GB, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
                _ => ListItems(EN, r)
                    .fake_with_rng::<Vec<String>, _>(rng)
                    .join("\n"),
            }
        }
        ("markdown", "blockquotesingleline") => {
            let r = count_range(spec, 1, 3);
            match loc {
                "fr_fr" => BlockQuoteSingleLine(FR_FR, r).fake_with_rng(rng),
                "de_de" => BlockQuoteSingleLine(DE_DE, r).fake_with_rng(rng),
                "it_it" => BlockQuoteSingleLine(IT_IT, r).fake_with_rng(rng),
                "pt_br" => BlockQuoteSingleLine(PT_BR, r).fake_with_rng(rng),
                "pt_pt" => BlockQuoteSingleLine(PT_PT, r).fake_with_rng(rng),
                "ar_sa" => BlockQuoteSingleLine(AR_SA, r).fake_with_rng(rng),
                "zh_cn" => BlockQuoteSingleLine(ZH_CN, r).fake_with_rng(rng),
                "zh_tw" => BlockQuoteSingleLine(ZH_TW, r).fake_with_rng(rng),
                "ja_jp" => BlockQuoteSingleLine(JA_JP, r).fake_with_rng(rng),
                "cy_gb" => BlockQuoteSingleLine(CY_GB, r).fake_with_rng(rng),
                _ => BlockQuoteSingleLine(EN, r).fake_with_rng(rng),
            }
        }
        ("markdown", "blockquotemultiline") => {
            let r = count_range(spec, 2, 4);
            match loc {
                "fr_fr" => BlockQuoteMultiLine(FR_FR, r).fake_with_rng::<Vec<String>, _>(rng),
                "de_de" => BlockQuoteMultiLine(DE_DE, r).fake_with_rng::<Vec<String>, _>(rng),
                "it_it" => BlockQuoteMultiLine(IT_IT, r).fake_with_rng::<Vec<String>, _>(rng),
                "pt_br" => BlockQuoteMultiLine(PT_BR, r).fake_with_rng::<Vec<String>, _>(rng),
                "pt_pt" => BlockQuoteMultiLine(PT_PT, r).fake_with_rng::<Vec<String>, _>(rng),
                "ar_sa" => BlockQuoteMultiLine(AR_SA, r).fake_with_rng::<Vec<String>, _>(rng),
                "zh_cn" => BlockQuoteMultiLine(ZH_CN, r).fake_with_rng::<Vec<String>, _>(rng),
                "zh_tw" => BlockQuoteMultiLine(ZH_TW, r).fake_with_rng::<Vec<String>, _>(rng),
                "ja_jp" => BlockQuoteMultiLine(JA_JP, r).fake_with_rng::<Vec<String>, _>(rng),
                "cy_gb" => BlockQuoteMultiLine(CY_GB, r).fake_with_rng::<Vec<String>, _>(rng),
                _ => BlockQuoteMultiLine(EN, r).fake_with_rng::<Vec<String>, _>(rng),
            }
            .join("\n")
        }
        ("markdown", "code") => {
            let r = count_range(spec, 3, 8);
            match loc {
                "fr_fr" => Code(FR_FR, r).fake_with_rng(rng),
                "de_de" => Code(DE_DE, r).fake_with_rng(rng),
                "it_it" => Code(IT_IT, r).fake_with_rng(rng),
                "pt_br" => Code(PT_BR, r).fake_with_rng(rng),
                "pt_pt" => Code(PT_PT, r).fake_with_rng(rng),
                "ar_sa" => Code(AR_SA, r).fake_with_rng(rng),
                "zh_cn" => Code(ZH_CN, r).fake_with_rng(rng),
                "zh_tw" => Code(ZH_TW, r).fake_with_rng(rng),
                "ja_jp" => Code(JA_JP, r).fake_with_rng(rng),
                "cy_gb" => Code(CY_GB, r).fake_with_rng(rng),
                _ => Code(EN, r).fake_with_rng(rng),
            }
        }

        ("number", "digit") => fl!(loc, rng, Digit),
        ("number", "numberwithformat") => {
            let fmt = spec.format.as_deref().unwrap_or("###-####").trim();
            if fmt.is_empty() {
                return None;
            }
            match loc {
                "fr_fr" => NumberWithFormat(FR_FR, fmt).fake_with_rng(rng),
                "de_de" => NumberWithFormat(DE_DE, fmt).fake_with_rng(rng),
                "it_it" => NumberWithFormat(IT_IT, fmt).fake_with_rng(rng),
                "pt_br" => NumberWithFormat(PT_BR, fmt).fake_with_rng(rng),
                "pt_pt" => NumberWithFormat(PT_PT, fmt).fake_with_rng(rng),
                "ar_sa" => NumberWithFormat(AR_SA, fmt).fake_with_rng(rng),
                "zh_cn" => NumberWithFormat(ZH_CN, fmt).fake_with_rng(rng),
                "zh_tw" => NumberWithFormat(ZH_TW, fmt).fake_with_rng(rng),
                "ja_jp" => NumberWithFormat(JA_JP, fmt).fake_with_rng(rng),
                "cy_gb" => NumberWithFormat(CY_GB, fmt).fake_with_rng(rng),
                _ => NumberWithFormat(EN, fmt).fake_with_rng(rng),
            }
        }

        ("boolean", "boolean") => {
            let ratio = spec.min.unwrap_or(50).clamp(0, 100) as u8;
            match loc {
                "fr_fr" => Boolean(FR_FR, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "de_de" => Boolean(DE_DE, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "it_it" => Boolean(IT_IT, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "pt_br" => Boolean(PT_BR, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "pt_pt" => Boolean(PT_PT, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "ar_sa" => Boolean(AR_SA, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "zh_cn" => Boolean(ZH_CN, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "zh_tw" => Boolean(ZH_TW, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "ja_jp" => Boolean(JA_JP, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                "cy_gb" => Boolean(CY_GB, ratio)
                    .fake_with_rng::<bool, _>(rng)
                    .to_string(),
                _ => Boolean(EN, ratio).fake_with_rng::<bool, _>(rng).to_string(),
            }
        }

        ("barcode", "isbn") => fl!(loc, rng, Isbn),
        ("barcode", "isbn10") => fl!(loc, rng, Isbn10),
        ("barcode", "isbn13") => fl!(loc, rng, Isbn13),

        ("creditcard", "creditcardnumber") => fl!(loc, rng, CreditCardNumber),

        ("currency", "currencycode") => fl!(loc, rng, CurrencyCode),
        ("currency", "currencyname") => fl!(loc, rng, CurrencyName),
        ("currency", "currencysymbol") => fl!(loc, rng, CurrencySymbol),

        ("finance", "bic") => fl!(loc, rng, Bic),
        ("finance", "isin") => fl!(loc, rng, Isin),

        ("filesystem", "filepath") => fl!(loc, rng, FilePath),
        ("filesystem", "filename") => fl!(loc, rng, FileName),
        ("filesystem", "fileextension") => fl!(loc, rng, FileExtension),
        ("filesystem", "dirpath") => fl!(loc, rng, DirPath),
        ("filesystem", "mimetype") => fl!(loc, rng, MimeType),
        ("filesystem", "semver") => fl!(loc, rng, Semver),
        ("filesystem", "semverstable") => fl!(loc, rng, SemverStable),
        ("filesystem", "semverunstable") => fl!(loc, rng, SemverUnstable),

        _ => return None,
    };

    Some(s)
}

/// Returns true if `spec` selects a built-in `fake` generator Dumpling knows how to call.
pub fn faker_path_supported(spec: &AnonymizerSpec) -> bool {
    let mut rng = StdRng::from_seed([0u8; 32]);
    faker_string_with_rng(spec, &mut rng).is_some()
}
