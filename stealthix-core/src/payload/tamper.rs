use base64::{engine::general_purpose, Engine as _};
use pyo3::prelude::*;
use regex::{Captures, Regex};
use std::sync::LazyLock;

static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]+").unwrap());
static PERCENT_HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%([0-9A-Fa-f]{2})").unwrap());
static ZEROX_HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"0x([0-9A-Fa-f]+)").unwrap());
static AND_WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bAND\b").unwrap());
static OR_WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bOR\b").unwrap());
static IF_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)IF\(([^,]+),([^,]+),([^\)]+)\)").unwrap());
static IFNULL_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)IFNULL\(([^,]+),([^\)]+)\)").unwrap());
static LIMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)LIMIT\s+(\d+)\s*,\s*(\d+)").unwrap());
static MID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)MID\(([^,]+),\s*([^,]+),\s*([^\)]+)\)").unwrap());
static COMMENT_PAREN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z_]+)\(").unwrap());
static GREATEST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(\b)([A-Za-z0-9_]+)\s*>\s*([A-Za-z0-9_]+)").unwrap());
static INFO_SCHEMA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)information_schema").unwrap());
static UNION_ALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)UNION\s+ALL\s+SELECT").unwrap());

fn sql_keywords() -> &'static [&'static str] {
    &[
        "ALL", "AND", "AS", "BY", "CASE", "FROM", "IF", "IN", "IS", "JOIN", "LIMIT", "MID", "NULL",
        "OR", "ORDER", "SELECT", "SLEEP", "THEN", "UNION", "WHEN", "WHERE",
    ]
}

fn is_keyword(word: &str) -> bool {
    sql_keywords()
        .iter()
        .any(|item| item.eq_ignore_ascii_case(word))
}

fn wrap_keywords(payload: &str, prefix: &str, suffix: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                format!("{prefix}{word}{suffix}")
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn random_comments(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if !is_keyword(word) || word.len() < 3 {
                return word.to_string();
            }
            let chars: Vec<char> = word.chars().collect();
            let middle = chars[1..chars.len() - 1]
                .iter()
                .map(|ch| ch.to_string())
                .collect::<Vec<_>>()
                .join("/**/");
            format!("{}{}{}", chars[0], middle, chars[chars.len() - 1])
        })
        .into_owned()
}

fn multiplespaces(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                format!("  {word}   ")
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn htmlencode(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() {
                ch.to_string()
            } else {
                format!("&#{};", ch as u32)
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn percentage(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_whitespace() {
                ch.to_string()
            } else {
                format!("%{ch}")
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn unicode_escape(payload: &str, web: bool) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_whitespace() {
                ch.to_string()
            } else if web {
                format!("%u{:04X}", ch as u32)
            } else {
                format!("\\u{:04x}", ch as u32)
            }
        })
        .collect::<Vec<_>>()
        .join("")
}

fn double_url_encode(payload: &str) -> String {
    PERCENT_HEX_RE
        .replace_all(payload, |caps: &Captures| {
            format!("%25{}", caps[1].to_ascii_uppercase())
        })
        .into_owned()
}

fn plus_to_concat(payload: &str, function_syntax: bool) -> String {
    if !payload.contains('+') {
        return payload.to_string();
    }
    let parts: Vec<String> = payload
        .split('+')
        .map(|part| part.trim().to_string())
        .collect();
    if parts.len() < 2 {
        return payload.to_string();
    }
    if function_syntax {
        format!("{{fn CONCAT({})}}", parts.join(","))
    } else {
        format!("CONCAT({})", parts.join(","))
    }
}

fn hex2char(payload: &str) -> String {
    ZEROX_HEX_RE
        .replace_all(payload, |caps: &Captures| {
            let hex = &caps[1];
            let chars = (0..hex.len())
                .step_by(2)
                .map(|index| {
                    let piece = &hex[index..usize::min(index + 2, hex.len())];
                    let value = u8::from_str_radix(piece, 16).unwrap_or_default();
                    format!("CHAR({value})")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("CONCAT({chars})")
        })
        .into_owned()
}

fn base64_encode(payload: &str) -> String {
    general_purpose::STANDARD.encode(payload)
}

fn base64url_encode(payload: &str) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(payload)
}

fn rot13(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                let base = if ch.is_ascii_lowercase() { b'a' } else { b'A' };
                let offset = (ch as u8 - base + 13) % 26;
                (base + offset) as char
            } else {
                ch
            }
        })
        .collect()
}

fn caesar(payload: &str, shift: i32) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphabetic() {
                let base = if ch.is_ascii_lowercase() { b'a' } else { b'A' };
                let offset = ((ch as u8 - base) as i32 + shift).rem_euclid(26) as u8;
                (base + offset) as char
            } else {
                ch
            }
        })
        .collect()
}

fn atbash(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() {
                (b'z' - (ch as u8 - b'a')) as char
            } else if ch.is_ascii_uppercase() {
                (b'Z' - (ch as u8 - b'A')) as char
            } else {
                ch
            }
        })
        .collect()
}

fn xor_encode(payload: &str, key: u8) -> String {
    payload
        .chars()
        .map(|ch| format!("{:02x}", (ch as u8) ^ key))
        .collect()
}

fn url_encode_all(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| format!("%{:02X}", ch as u8))
        .collect()
}

fn triple_url_encode(payload: &str) -> String {
    let double = double_url_encode(payload);
    double_url_encode(&double)
}

fn mixed_encode(payload: &str) -> String {
    let mut result = String::new();
    for (i, ch) in payload.chars().enumerate() {
        if i % 3 == 0 {
            result.push_str(&format!("%{:02X}", ch as u8));
        } else if i % 3 == 1 {
            result.push(ch);
        } else {
            result.push_str(&format!("&#{};", ch as u32));
        }
    }
    result
}

fn inline_comment_dash(payload: &str) -> String {
    payload.replace(' ', "--")
}

fn inline_comment_hash(payload: &str) -> String {
    payload.replace(' ', "#")
}

fn block_comment_mysql(payload: &str) -> String {
    payload.replace(' ', "/* */")
}

fn block_comment_pg(payload: &str) -> String {
    payload.replace(' ', "/**/")
}

fn nested_comments(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                format!("/*{}*/", word)
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn keyword_casing_random(payload: &str) -> String {
    let mut rng: i32 = 12345; // Simple deterministic seed
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
                if rng % 2 == 0 {
                    word.to_ascii_uppercase()
                } else {
                    word.to_ascii_lowercase()
                }
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn keyword_casing_upper(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                word.to_ascii_uppercase()
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn keyword_casing_lower(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                word.to_ascii_lowercase()
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn keyword_obfuscation(payload: &str) -> String {
    IDENT_RE
        .replace_all(payload, |caps: &Captures| {
            let word = &caps[0];
            if is_keyword(word) {
                let obfuscated: String = word
                    .chars()
                    .enumerate()
                    .map(|(i, ch)| {
                        if i % 2 == 0 {
                            ch.to_ascii_uppercase()
                        } else {
                            ch.to_ascii_lowercase()
                        }
                    })
                    .collect();
                obfuscated
            } else {
                word.to_string()
            }
        })
        .into_owned()
}

fn keyword_substitution(payload: &str) -> String {
    let substitutions = [
        ("SELECT", "/*!SELECT*/"),
        ("UNION", "/*!UNION*/"),
        ("WHERE", "/*!WHERE*/"),
        ("AND", "/*!AND*/"),
        ("OR", "/*!OR*/"),
    ];
    let mut result = payload.to_string();
    for (keyword, replacement) in &substitutions {
        result = Regex::new(&format!("(?i){}", keyword))
            .unwrap()
            .replace_all(&result, *replacement)
            .into_owned();
    }
    result
}

fn space2null(payload: &str) -> String {
    payload.replace(' ', "%00")
}

fn space2newline(payload: &str) -> String {
    payload.replace(' ', "%0A")
}

fn space2cr(payload: &str) -> String {
    payload.replace(' ', "%0D")
}

fn space2formfeed(payload: &str) -> String {
    payload.replace(' ', "%0C")
}

fn space2verticaltab(payload: &str) -> String {
    payload.replace(' ', "%0B")
}

fn operator_substitution(payload: &str) -> String {
    payload
        .replace('=', "==")
        .replace(">", ">>")
        .replace("<", "<<")
}

fn operator_obfuscation(payload: &str) -> String {
    payload
        .replace('=', "/*!=*/")
        .replace(">", "/**/>")
        .replace("<", "/**/<")
}

fn logical_substitution(payload: &str) -> String {
    Regex::new(r"(?i)\bAND\b")
        .unwrap()
        .replace_all(payload, "&&")
        .into_owned()
        .replace("||", "OR")
}

fn comparison_substitution(payload: &str) -> String {
    payload
        .replace('=', "LIKE")
        .replace(">", ">=")
        .replace("<", "<=")
}

fn concat_substitution(payload: &str) -> String {
    payload.replace('+', "||").replace("CONCAT", "||")
}

fn stacked_queries(payload: &str) -> String {
    format!("{}; {}", payload, payload)
}

fn time_based_obfuscation(payload: &str) -> String {
    format!("{} AND SLEEP(1)", payload)
}

fn error_based_obfuscation(payload: &str) -> String {
    format!("{} AND 1=CAST(1/0 AS INT)", payload)
}

fn union_obfuscation(payload: &str) -> String {
    payload.replace("UNION", "/*!00000UNION*/")
}

fn conditional_obfuscation(payload: &str) -> String {
    IF_CALL_RE
        .replace_all(payload, |caps: &Captures| {
            format!(
                "CASE WHEN {} THEN {} ELSE {} END",
                caps[1].trim(),
                caps[2].trim(),
                caps[3].trim()
            )
        })
        .into_owned()
}

fn apply_named(script: &str, payload: &str) -> String {
    match script {
        "apostrophemask" => payload.replace('\'', "%EF%BC%87"),
        "apostrophenullencode" => payload.replace('\'', "%00%27"),
        "appendnullbyte" => {
            if payload.ends_with("%00") {
                payload.to_string()
            } else {
                format!("{payload}%00")
            }
        }
        "chardoubleencode" => double_url_encode(payload),
        "charunicodeencode" => unicode_escape(payload, true),
        "charunicodeescape" => unicode_escape(payload, false),
        "commalesslimit" => LIMIT_RE
            .replace_all(payload, |caps: &Captures| {
                format!("LIMIT {} OFFSET {}", &caps[2], &caps[1])
            })
            .into_owned(),
        "commalessmid" => MID_RE
            .replace_all(payload, |caps: &Captures| {
                format!("MID({} FROM {} FOR {})", &caps[1], &caps[2], &caps[3])
            })
            .into_owned(),
        "commentbeforeparentheses" => COMMENT_PAREN_RE
            .replace_all(payload, "$1/**/(")
            .into_owned(),
        "greatest" => GREATEST_RE
            .replace_all(payload, |caps: &Captures| {
                format!(
                    "{}GREATEST({},{}+1)={}",
                    &caps[1], &caps[2], &caps[3], &caps[2]
                )
            })
            .into_owned(),
        "halfversionedmorekeywords" => wrap_keywords(payload, "/*!0", "*/"),
        "hex2char" => hex2char(payload),
        "htmlencode" => htmlencode(payload),
        "if2case" => IF_CALL_RE
            .replace_all(payload, |caps: &Captures| {
                format!(
                    "CASE WHEN ({}) THEN ({}) ELSE ({}) END",
                    caps[1].trim(),
                    caps[2].trim(),
                    caps[3].trim()
                )
            })
            .into_owned(),
        "ifnull2casewhenisnull" => IFNULL_CALL_RE
            .replace_all(payload, |caps: &Captures| {
                format!(
                    "CASE WHEN ISNULL({}) THEN ({}) ELSE ({}) END",
                    caps[1].trim(),
                    caps[2].trim(),
                    caps[1].trim()
                )
            })
            .into_owned(),
        "informationschemacomment" => INFO_SCHEMA_RE
            .replace_all(payload, "information_schema/**/")
            .into_owned(),
        "lowercase" => IDENT_RE
            .replace_all(payload, |caps: &Captures| {
                let word = &caps[0];
                if is_keyword(word) {
                    word.to_ascii_lowercase()
                } else {
                    word.to_string()
                }
            })
            .into_owned(),
        "multiplespaces" => multiplespaces(payload),
        "percentage" => percentage(payload),
        "plus2concat" => plus_to_concat(payload, false),
        "plus2fnconcat" => plus_to_concat(payload, true),
        "randomcomments" => random_comments(payload),
        "sp_password" => {
            if payload.to_ascii_lowercase().ends_with("sp_password") {
                payload.to_string()
            } else {
                format!("{payload}-- sp_password")
            }
        }
        "symboliclogical" => AND_WORD_RE
            .replace_all(
                &OR_WORD_RE.replace_all(payload, "%7C%7C"),
                "%26%26",
            )
            .into_owned(),
        "unionalltounion" | "unionalltoinon" => UNION_ALL_RE
            .replace_all(payload, "UNION SELECT")
            .into_owned(),
        "unmagicquotes" => payload.replace('\'', "%bf%27").replace("-- ", "%23"),
        "uppercase" => IDENT_RE
            .replace_all(payload, |caps: &Captures| {
                let word = &caps[0];
                if is_keyword(word) {
                    word.to_ascii_uppercase()
                } else {
                    word.to_string()
                }
            })
            .into_owned(),
        "versionedkeywords" => wrap_keywords(payload, "/*!", "*/"),
        "versionedmorekeywords" => wrap_keywords(payload, "/*!50000 ", "*/"),
        "reverse" => payload.chars().rev().collect(),
        "inline_comment" | "space2comment" => payload.replace(' ', "/**/"),
        "space2plus" => payload.replace(' ', "+"),
        "space2tab" => payload.replace(' ', "%09"),
        "randomcase" => {
            let mut upper = false;
            let mut out = String::with_capacity(payload.len());
            for ch in payload.chars() {
                if ch.is_ascii_alphabetic() {
                    out.push(if upper {
                        ch.to_ascii_uppercase()
                    } else {
                        ch.to_ascii_lowercase()
                    });
                    upper = !upper;
                } else {
                    out.push(ch);
                }
            }
            out
        }
        "between" => payload.replace("AND", "A/**/ND").replace("OR", "O/**/R"),
        "union_all" => payload.replace("UNION", "UNION ALL"),
        "eq2like" => payload.replace('=', " LIKE "),
        "utf8" => payload
            .chars()
            .map(|ch| format!("&#{};", ch as u32))
            .collect::<Vec<_>>()
            .join(""),
        "charencode" => payload
            .chars()
            .map(|ch| format!("CHAR({})", ch as u32))
            .collect::<Vec<_>>()
            .join(","),
        // New tamper scripts
        "base64encode" => base64_encode(payload),
        "base64url" => base64url_encode(payload),
        "rot13" => rot13(payload),
        "caesar" => caesar(payload, 3),
        "atbash" => atbash(payload),
        "xor" => xor_encode(payload, 42),
        "url_encode_all" => url_encode_all(payload),
        "double_encode" => double_url_encode(payload),
        "triple_encode" => triple_url_encode(payload),
        "mixed_encode" => mixed_encode(payload),
        "inline_comment_dash" => inline_comment_dash(payload),
        "inline_comment_hash" => inline_comment_hash(payload),
        "block_comment_mysql" => block_comment_mysql(payload),
        "block_comment_pg" => block_comment_pg(payload),
        "nested_comments" => nested_comments(payload),
        "keyword_casing_random" => keyword_casing_random(payload),
        "keyword_casing_upper" => keyword_casing_upper(payload),
        "keyword_casing_lower" => keyword_casing_lower(payload),
        "keyword_obfuscation" => keyword_obfuscation(payload),
        "keyword_substitution" => keyword_substitution(payload),
        "space2null" => space2null(payload),
        "space2newline" => space2newline(payload),
        "space2cr" => space2cr(payload),
        "space2formfeed" => space2formfeed(payload),
        "space2verticaltab" => space2verticaltab(payload),
        "operator_substitution" => operator_substitution(payload),
        "operator_obfuscation" => operator_obfuscation(payload),
        "logical_substitution" => logical_substitution(payload),
        "comparison_substitution" => comparison_substitution(payload),
        "concat_substitution" => concat_substitution(payload),
        "stacked_queries" => stacked_queries(payload),
        "time_based_obfuscation" => time_based_obfuscation(payload),
        "error_based_obfuscation" => error_based_obfuscation(payload),
        "union_obfuscation" => union_obfuscation(payload),
        "conditional_obfuscation" => conditional_obfuscation(payload),
        _ => payload.to_string(),
    }
}

#[pyfunction]
pub fn apply_tamper(script: String, payload: String) -> String {
    apply_named(&script.to_ascii_lowercase(), &payload)
}

#[pyfunction]
pub fn apply_tamper_sequence(scripts: Vec<String>, payload: String) -> String {
    scripts.into_iter().fold(payload, |current, script| {
        apply_named(&script.to_ascii_lowercase(), &current)
    })
}

#[pyfunction]
pub fn list_tamper_scripts() -> Vec<&'static str> {
    vec![
        "apostrophemask",
        "apostrophenullencode",
        "appendnullbyte",
        "between",
        "charencode",
        "chardoubleencode",
        "charunicodeencode",
        "charunicodeescape",
        "commalesslimit",
        "commalessmid",
        "commentbeforeparentheses",
        "eq2like",
        "greatest",
        "halfversionedmorekeywords",
        "hex2char",
        "htmlencode",
        "if2case",
        "ifnull2casewhenisnull",
        "informationschemacomment",
        "inline_comment",
        "lowercase",
        "multiplespaces",
        "percentage",
        "plus2concat",
        "plus2fnconcat",
        "randomcase",
        "randomcomments",
        "reverse",
        "space2comment",
        "space2plus",
        "space2tab",
        "sp_password",
        "symboliclogical",
        "union_all",
        "unionalltounion",
        "unionalltoinon",
        "unmagicquotes",
        "uppercase",
        "utf8",
        "varnish",
        "versionedkeywords",
        "versionedmorekeywords",
        "xforwardedfor",
        // New tamper scripts
        "base64encode",
        "base64url",
        "rot13",
        "caesar",
        "atbash",
        "xor",
        "url_encode_all",
        "double_encode",
        "triple_encode",
        "mixed_encode",
        "inline_comment_dash",
        "inline_comment_hash",
        "block_comment_mysql",
        "block_comment_pg",
        "nested_comments",
        "keyword_casing_random",
        "keyword_casing_upper",
        "keyword_casing_lower",
        "keyword_obfuscation",
        "keyword_substitution",
        "space2null",
        "space2newline",
        "space2cr",
        "space2formfeed",
        "space2verticaltab",
        "operator_substitution",
        "operator_obfuscation",
        "logical_substitution",
        "comparison_substitution",
        "concat_substitution",
        "stacked_queries",
        "time_based_obfuscation",
        "error_based_obfuscation",
        "union_obfuscation",
        "conditional_obfuscation",
    ]
}

#[pyfunction]
pub fn tamper_reverse(payload: String) -> String {
    apply_named("reverse", &payload)
}
#[pyfunction]
pub fn tamper_inline_comment(payload: String) -> String {
    apply_named("inline_comment", &payload)
}
#[pyfunction]
pub fn tamper_space2comment(payload: String) -> String {
    apply_named("space2comment", &payload)
}
#[pyfunction]
pub fn tamper_space2plus(payload: String) -> String {
    apply_named("space2plus", &payload)
}
#[pyfunction]
pub fn tamper_space2tab(payload: String) -> String {
    apply_named("space2tab", &payload)
}
#[pyfunction]
pub fn tamper_randomcase(payload: String) -> String {
    apply_named("randomcase", &payload)
}
#[pyfunction]
pub fn tamper_between(payload: String) -> String {
    apply_named("between", &payload)
}
#[pyfunction]
pub fn tamper_union_all(payload: String) -> String {
    apply_named("union_all", &payload)
}
#[pyfunction]
pub fn tamper_eq2like(payload: String) -> String {
    apply_named("eq2like", &payload)
}
#[pyfunction]
pub fn tamper_utf8(payload: String) -> String {
    apply_named("utf8", &payload)
}
#[pyfunction]
pub fn tamper_charencode(payload: String) -> String {
    apply_named("charencode", &payload)
}

// New tamper functions
#[pyfunction]
pub fn tamper_base64encode(payload: String) -> String {
    apply_named("base64encode", &payload)
}
#[pyfunction]
pub fn tamper_base64url(payload: String) -> String {
    apply_named("base64url", &payload)
}
#[pyfunction]
pub fn tamper_rot13(payload: String) -> String {
    apply_named("rot13", &payload)
}
#[pyfunction]
pub fn tamper_caesar(payload: String) -> String {
    apply_named("caesar", &payload)
}
#[pyfunction]
pub fn tamper_atbash(payload: String) -> String {
    apply_named("atbash", &payload)
}
#[pyfunction]
pub fn tamper_xor(payload: String) -> String {
    apply_named("xor", &payload)
}
#[pyfunction]
pub fn tamper_url_encode_all(payload: String) -> String {
    apply_named("url_encode_all", &payload)
}
#[pyfunction]
pub fn tamper_double_encode(payload: String) -> String {
    apply_named("double_encode", &payload)
}
#[pyfunction]
pub fn tamper_triple_encode(payload: String) -> String {
    apply_named("triple_encode", &payload)
}
#[pyfunction]
pub fn tamper_mixed_encode(payload: String) -> String {
    apply_named("mixed_encode", &payload)
}
#[pyfunction]
pub fn tamper_inline_comment_dash(payload: String) -> String {
    apply_named("inline_comment_dash", &payload)
}
#[pyfunction]
pub fn tamper_inline_comment_hash(payload: String) -> String {
    apply_named("inline_comment_hash", &payload)
}
#[pyfunction]
pub fn tamper_block_comment_mysql(payload: String) -> String {
    apply_named("block_comment_mysql", &payload)
}
#[pyfunction]
pub fn tamper_block_comment_pg(payload: String) -> String {
    apply_named("block_comment_pg", &payload)
}
#[pyfunction]
pub fn tamper_nested_comments(payload: String) -> String {
    apply_named("nested_comments", &payload)
}
#[pyfunction]
pub fn tamper_keyword_casing_random(payload: String) -> String {
    apply_named("keyword_casing_random", &payload)
}
#[pyfunction]
pub fn tamper_keyword_casing_upper(payload: String) -> String {
    apply_named("keyword_casing_upper", &payload)
}
#[pyfunction]
pub fn tamper_keyword_casing_lower(payload: String) -> String {
    apply_named("keyword_casing_lower", &payload)
}
#[pyfunction]
pub fn tamper_keyword_obfuscation(payload: String) -> String {
    apply_named("keyword_obfuscation", &payload)
}
#[pyfunction]
pub fn tamper_keyword_substitution(payload: String) -> String {
    apply_named("keyword_substitution", &payload)
}
#[pyfunction]
pub fn tamper_space2null(payload: String) -> String {
    apply_named("space2null", &payload)
}
#[pyfunction]
pub fn tamper_space2newline(payload: String) -> String {
    apply_named("space2newline", &payload)
}
#[pyfunction]
pub fn tamper_space2cr(payload: String) -> String {
    apply_named("space2cr", &payload)
}
#[pyfunction]
pub fn tamper_space2formfeed(payload: String) -> String {
    apply_named("space2formfeed", &payload)
}
#[pyfunction]
pub fn tamper_space2verticaltab(payload: String) -> String {
    apply_named("space2verticaltab", &payload)
}
#[pyfunction]
pub fn tamper_operator_substitution(payload: String) -> String {
    apply_named("operator_substitution", &payload)
}
#[pyfunction]
pub fn tamper_operator_obfuscation(payload: String) -> String {
    apply_named("operator_obfuscation", &payload)
}
#[pyfunction]
pub fn tamper_logical_substitution(payload: String) -> String {
    apply_named("logical_substitution", &payload)
}
#[pyfunction]
pub fn tamper_comparison_substitution(payload: String) -> String {
    apply_named("comparison_substitution", &payload)
}
#[pyfunction]
pub fn tamper_concat_substitution(payload: String) -> String {
    apply_named("concat_substitution", &payload)
}
#[pyfunction]
pub fn tamper_stacked_queries(payload: String) -> String {
    apply_named("stacked_queries", &payload)
}
#[pyfunction]
pub fn tamper_time_based_obfuscation(payload: String) -> String {
    apply_named("time_based_obfuscation", &payload)
}
#[pyfunction]
pub fn tamper_error_based_obfuscation(payload: String) -> String {
    apply_named("error_based_obfuscation", &payload)
}
#[pyfunction]
pub fn tamper_union_obfuscation(payload: String) -> String {
    apply_named("union_obfuscation", &payload)
}
#[pyfunction]
pub fn tamper_conditional_obfuscation(payload: String) -> String {
    apply_named("conditional_obfuscation", &payload)
}

#[pymodule]
pub fn tamper(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(apply_tamper, m)?)?;
    m.add_function(wrap_pyfunction!(apply_tamper_sequence, m)?)?;
    m.add_function(wrap_pyfunction!(list_tamper_scripts, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_reverse, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_inline_comment, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2comment, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2plus, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2tab, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_randomcase, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_between, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_union_all, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_eq2like, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_utf8, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_charencode, m)?)?;
    // New tamper functions
    m.add_function(wrap_pyfunction!(tamper_base64encode, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_base64url, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_rot13, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_caesar, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_atbash, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_xor, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_url_encode_all, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_double_encode, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_triple_encode, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_mixed_encode, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_inline_comment_dash, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_inline_comment_hash, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_block_comment_mysql, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_block_comment_pg, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_nested_comments, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_keyword_casing_random, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_keyword_casing_upper, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_keyword_casing_lower, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_keyword_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_keyword_substitution, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2null, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2newline, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2cr, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2formfeed, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_space2verticaltab, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_operator_substitution, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_operator_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_logical_substitution, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_comparison_substitution, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_concat_substitution, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_stacked_queries, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_time_based_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_error_based_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_union_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(tamper_conditional_obfuscation, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_named, list_tamper_scripts};

    #[test]
    fn unionalltoinon_alias_rewrites_payload() {
        let out = apply_named("unionalltoinon", "1 UNION ALL SELECT 1");
        assert_eq!(out, "1 UNION SELECT 1");
    }

    #[test]
    fn sqlmap_scripts_are_listed() {
        assert!(list_tamper_scripts().contains(&"versionedmorekeywords"));
        assert!(list_tamper_scripts().contains(&"xforwardedfor"));
    }
}
