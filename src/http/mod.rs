#![allow(dead_code)]

use serde::Deserialize;

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
