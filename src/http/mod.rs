#![allow(dead_code)]

use serde::{de, Deserialize, Deserializer};

pub mod apis;
pub mod models;

pub(crate) fn parse_json<'de, T>(
    j: &'de str,
) -> Result<T, serde_path_to_error::Error<serde_json::Error>>
where
    T: Deserialize<'de>,
{
    let jd = &mut serde_json::Deserializer::from_str(j);
    let result: T = serde_path_to_error::deserialize(jd)?;
    Ok(result)
}

pub fn deserialize_number_from_string<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i64),
        Float(f64),
        Null,
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => {
            let f = s
                .parse::<f64>()
                .map_err(|_| de::Error::custom("Failed to parse inner number"))?;
            Ok(Some(f))
        }
        StringOrNumber::Number(i) => Ok(Some(i as f64)),
        StringOrNumber::Float(f) => Ok(Some(f)),
        StringOrNumber::Null => Ok(None),
    }
}

pub fn deserialize_integer_from_string<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i32),
        Null,
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => {
            let i = s
                .parse::<i32>()
                .map_err(|_| de::Error::custom("Failed to parse inner number"))?;
            Ok(Some(i))
        }
        StringOrNumber::Number(i) => Ok(Some(i)),
        StringOrNumber::Null => Ok(None),
    }
}

pub fn deserialize_string_from_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i64),
        Float(f64),
        Null,
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => Ok(Some(s)),
        StringOrNumber::Number(i) => Ok(Some(i.to_string())),
        StringOrNumber::Float(f) => Ok(Some(f.to_string())),
        StringOrNumber::Null => Ok(None),
    }
}

pub fn deserialize_string_from_number_required<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNumber {
        String(String),
        Number(i64),
        Float(f64),
    }

    match StringOrNumber::deserialize(deserializer)? {
        StringOrNumber::String(s) => Ok(s),
        StringOrNumber::Number(i) => Ok(i.to_string()),
        StringOrNumber::Float(f) => Ok(f.to_string()),
    }
}

pub fn deserialize_bool_from_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrBool<'a> {
        String(&'a str),
        Bool(bool),
        Null,
    }

    match StringOrBool::deserialize(deserializer)? {
        StringOrBool::String("true") => Ok(Some(true)),
        StringOrBool::String("false") => Ok(Some(false)),
        StringOrBool::String(s) => Err(de::Error::unknown_variant(s, &["true", "false"])),
        StringOrBool::Bool(b) => Ok(Some(b)),
        StringOrBool::Null => Ok(None),
    }
}
