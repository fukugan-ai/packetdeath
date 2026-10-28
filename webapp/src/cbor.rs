//! A small CBOR reader for the answers of an authenticator. `webapp/docs/design.ja.md` stage 14.
//!
//! It reads integers, byte strings, text strings, arrays and maps of a known
//! length, and nothing else: no floats, no tags, no indefinite lengths. Anything
//! else is an error, so a crafted answer cannot make it guess. Depth and sizes
//! are bounded.

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CborError {
    /// The input ends inside an item.
    Short,
    /// A type or a length form this reader does not take.
    Unsupported,
    /// Nesting or an item count above the limit.
    TooBig,
    /// A text string that is not UTF-8.
    NotText,
}

/// Read one item from the start of `bytes`. Returns it and how many bytes it took.
pub fn read(bytes: &[u8]) -> Result<(Value, usize), CborError> {
    item(bytes, 0, 0)
}

/// Read one item that must fill `bytes` exactly.
pub fn read_all(bytes: &[u8]) -> Result<Value, CborError> {
    let (found, used) = read(bytes)?;
    if used != bytes.len() {
        return Err(CborError::Unsupported);
    }
    Ok(found)
}

fn take(bytes: &[u8], at: usize, count: usize) -> Result<&[u8], CborError> {
    let end = at.checked_add(count).ok_or(CborError::Short)?;
    bytes.get(at..end).ok_or(CborError::Short)
}

/// The argument of the item that starts at `at`: its major type, the number, and the position after the head.
fn head(bytes: &[u8], at: usize) -> Result<(u8, u64, usize), CborError> {
    let first = *bytes.get(at).ok_or(CborError::Short)?;
    let (major, info) = (first >> 5, first & 0x1f);
    let (width, inline) = match info {
        0..=23 => (0, Some(u64::from(info))),
        24 => (1, None),
        25 => (2, None),
        26 => (4, None),
        27 => (8, None),
        _ => return Err(CborError::Unsupported),
    };
    if let Some(number) = inline {
        return Ok((major, number, at + 1));
    }
    let raw = take(bytes, at + 1, width)?;
    let number = raw.iter().fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte));
    Ok((major, number, at + 1 + width))
}

fn item(bytes: &[u8], at: usize, depth: usize) -> Result<(Value, usize), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::TooBig);
    }
    let (major, number, body) = head(bytes, at)?;
    match major {
        0 => Ok((Value::Int(i64::try_from(number).map_err(|_| CborError::Unsupported)?), body)),
        1 => {
            let positive = i64::try_from(number).map_err(|_| CborError::Unsupported)?;
            Ok((Value::Int(-1 - positive), body))
        }
        2 | 3 => {
            let length = usize::try_from(number).map_err(|_| CborError::TooBig)?;
            let raw = take(bytes, body, length)?;
            if major == 2 {
                return Ok((Value::Bytes(raw.to_vec()), body + length));
            }
            let text = std::str::from_utf8(raw).map_err(|_| CborError::NotText)?;
            Ok((Value::Text(text.to_owned()), body + length))
        }
        4 | 5 => {
            if number > MAX_ITEMS {
                return Err(CborError::TooBig);
            }
            let mut position = body;
            let mut items = Vec::new();
            let count = if major == 5 { number * 2 } else { number };
            for _ in 0..count {
                let (next, after) = item(bytes, position, depth + 1)?;
                items.push(next);
                position = after;
            }
            if major == 4 {
                return Ok((Value::Array(items), position));
            }
            let mut pairs = Vec::new();
            let mut walk = items.into_iter();
            while let (Some(key), Some(value)) = (walk.next(), walk.next()) {
                pairs.push((key, value));
            }
            Ok((Value::Map(pairs), position))
        }
        _ => Err(CborError::Unsupported),
    }
}

impl Value {
    /// The value under an integer key of a map.
    pub fn by_int(&self, key: i64) -> Option<&Value> {
        let Value::Map(pairs) = self else { return None };
        pairs.iter().find(|(k, _)| *k == Value::Int(key)).map(|(_, v)| v)
    }

    /// The value under a text key of a map.
    pub fn by_text(&self, key: &str) -> Option<&Value> {
        let Value::Map(pairs) = self else { return None };
        pairs.iter().find(|(k, _)| matches!(k, Value::Text(text) if text == key)).map(|(_, v)| v)
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(raw) => Some(raw),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(number) => Some(*number),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8949_appendix_a_examples_read() -> Result<(), CborError> {
        assert_eq!(read_all(&[0x00])?, Value::Int(0));
        assert_eq!(read_all(&[0x18, 0x64])?, Value::Int(100));
        assert_eq!(read_all(&[0x20])?, Value::Int(-1));
        assert_eq!(read_all(&[0x39, 0x03, 0xe7])?, Value::Int(-1000));
        assert_eq!(read_all(&[0x44, 1, 2, 3, 4])?, Value::Bytes(vec![1, 2, 3, 4]));
        assert_eq!(read_all(&[0x64, 0x49, 0x45, 0x54, 0x46])?, Value::Text(String::from("IETF")));
        assert_eq!(read_all(&[0x83, 0x01, 0x02, 0x03])?, Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]));
        let map = read_all(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03])?;
        assert_eq!(map.by_text("a").and_then(Value::as_int), Some(1));
        assert!(matches!(map.by_text("b"), Some(Value::Array(rows)) if rows.len() == 2));
        Ok(())
    }

    #[test]
    fn a_cose_key_map_reads_by_integer_keys() -> Result<(), CborError> {
        // {1: 2, 3: -7, -1: 1}
        let key = read_all(&[0xa3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01])?;
        assert_eq!(key.by_int(1).and_then(Value::as_int), Some(2));
        assert_eq!(key.by_int(3).and_then(Value::as_int), Some(-7));
        assert_eq!(key.by_int(-1).and_then(Value::as_int), Some(1));
        assert_eq!(key.by_int(9), None);
        Ok(())
    }

    #[test]
    fn the_length_of_the_first_item_is_reported() -> Result<(), CborError> {
        let (found, used) = read(&[0x82, 0x01, 0x02, 0xff, 0xff])?;
        assert_eq!(found, Value::Array(vec![Value::Int(1), Value::Int(2)]));
        assert_eq!(used, 3);
        Ok(())
    }

    #[test]
    fn short_odd_and_oversized_input_is_an_error() {
        assert_eq!(read(&[]), Err(CborError::Short));
        assert_eq!(read(&[0x44, 1, 2]), Err(CborError::Short));
        assert_eq!(read(&[0x5f]), Err(CborError::Unsupported), "indefinite length");
        assert_eq!(read(&[0xf9, 0x3c, 0x00]), Err(CborError::Unsupported), "a float");
        assert_eq!(read(&[0xc0, 0x00]), Err(CborError::Unsupported), "a tag");
        assert_eq!(read(&[0x62, 0xff, 0xfe]), Err(CborError::NotText));
        assert_eq!(read(&[0x98, 0x41]), Err(CborError::TooBig), "an array above the item limit");
        assert_eq!(read_all(&[0x00, 0x00]), Err(CborError::Unsupported), "trailing bytes");
        let deep = vec![0x81; MAX_DEPTH + 3];
        assert_eq!(read(&deep), Err(CborError::TooBig));
    }
}
