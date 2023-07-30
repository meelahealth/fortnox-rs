use std::fmt::{Display, Write};

use uuid::Uuid;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomerId<const P: char = 'A'>(Uuid);

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid prefix: {0}")]
    InvalidPrefix(char),
}

const FORMAT: u128 = lexical::NumberFormatBuilder::new().radix(32).build();

impl<const P: char> CustomerId<P> {
    pub fn random() -> Self {
        CustomerId(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        CustomerId(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub fn from_str(s: &str) -> Result<Self, Error> {
        let mut chunks = s.split('-');
        let Some(first_char) = chunks.next().and_then(|x| x.chars().next()) else {
            return Err(Error::InvalidInput(s.to_string()));
        };

        if first_char != P {
            return Err(Error::InvalidPrefix(first_char));
        }

        if let Some(chunk) = chunks.next() {
            let result = lexical::parse_with_options::<u128, _, FORMAT>(
                chunk.as_bytes(),
                &Default::default(),
            );
            match result {
                Ok(v) => Ok(Self(Uuid::from_u128(v))),
                Err(_e) => Err(Error::InvalidInput(s.to_string())),
            }
        } else {
            return Err(Error::InvalidInput(s.to_string()));
        }
    }
}

impl<const P: char> Display for CustomerId<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out =
            lexical::to_string_with_options::<_, FORMAT>(self.0.as_u128(), &Default::default());
        f.write_char(P)?;
        f.write_char('-')?;
        f.write_str(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_customer_id() {
        let x = Uuid::new_v4();
        let id = CustomerId::<'T'>::from_uuid(x);
        assert_eq!(id.as_uuid(), x);

        let id32 = id.to_string();
        let id2 = CustomerId::<'T'>::from_str(&id32).unwrap();
        assert_eq!(id, id2);

        let id3 = CustomerId::<'T'>::from_uuid(id.as_uuid());
        assert_eq!(id, id3);
    }
}
