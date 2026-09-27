//! nargo's ABI, for what the prover needs: parameter and return types (to
//! count fields) and `Prover.toml` encoding in witness order.
//!
//! Supports the ABI kinds `noir-zk-codegen` generates types for: fields,
//! booleans, unsigned integers, arrays and structs. Encoding is strict: every
//! parameter and struct field must be present, nothing else may be, and each
//! value must fit its type (no reduction modulo the field).

use noir_zk_core::codec::field_from_be_bytes_canonical;
use noir_zk_core::{Error, Field};
use serde_json::Value;

/// An ABI type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    /// A field element.
    Field,
    /// A boolean.
    Boolean,
    /// An unsigned integer of this many bits.
    Unsigned(u32),
    /// A fixed-length array.
    Array(usize, Box<Type>),
    /// A struct: its fields in declaration order.
    Struct(Vec<(String, Type)>),
}

impl Type {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let bad = || Error::Artifact(format!("unsupported ABI type {v}"));
        Ok(match v["kind"].as_str() {
            Some("field") => Self::Field,
            Some("boolean") => Self::Boolean,
            Some("integer") if v["sign"] == "unsigned" => Self::Unsigned(
                v["width"]
                    .as_u64()
                    .and_then(|w| u32::try_from(w).ok())
                    .ok_or_else(bad)?,
            ),
            Some("array") => Self::Array(
                v["length"]
                    .as_u64()
                    .and_then(|l| usize::try_from(l).ok())
                    .ok_or_else(bad)?,
                Box::new(Self::from_json(&v["type"])?),
            ),
            Some("struct") => Self::Struct(
                v["fields"]
                    .as_array()
                    .ok_or_else(bad)?
                    .iter()
                    .map(|f| {
                        Ok((
                            f["name"].as_str().ok_or_else(bad)?.to_string(),
                            Self::from_json(&f["type"])?,
                        ))
                    })
                    .collect::<Result<_, Error>>()?,
            ),
            _ => return Err(bad()),
        })
    }

    /// Field elements a value of this type spans.
    pub fn field_count(&self) -> usize {
        match self {
            Self::Field | Self::Boolean | Self::Unsigned(_) => 1,
            Self::Array(n, t) => n * t.field_count(),
            Self::Struct(fs) => fs.iter().map(|(_, t)| t.field_count()).sum(),
        }
    }

    fn encode(&self, v: &toml::Value, at: &str, out: &mut Vec<Field>) -> Result<(), Error> {
        let bad = |why: &str| Error::Abi(format!("{at}: {why}"));
        match (self, v) {
            (Self::Boolean, toml::Value::Boolean(b)) => out.push(Field::from(u8::from(*b))),
            (Self::Field, _) => out.push(field_of(v).ok_or_else(|| bad("not a field element"))?),
            (Self::Unsigned(bits), _) => {
                let f = field_of(v).ok_or_else(|| bad("not an unsigned integer"))?;
                if bit_length(&f) > *bits {
                    return Err(bad(&format!("exceeds {bits} bits")));
                }
                out.push(f);
            }
            (Self::Array(n, t), toml::Value::Array(items)) => {
                if items.len() != *n {
                    return Err(bad(&format!("{} elements, expected {n}", items.len())));
                }
                for (i, item) in items.iter().enumerate() {
                    t.encode(item, &format!("{at}[{i}]"), out)?;
                }
            }
            (Self::Struct(fs), toml::Value::Table(table)) => encode_table(fs, table, at, out)?,
            _ => return Err(bad(&format!("expected {self:?}"))),
        }
        Ok(())
    }
}

/// A field element from a TOML string (`0x` hex or decimal) or non-negative
/// integer; `None` unless it is below the modulus.
fn field_of(v: &toml::Value) -> Option<Field> {
    let s = match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) if *i >= 0 => i.to_string(),
        _ => return None,
    };
    let bytes = if let Some(h) = s.strip_prefix("0x") {
        let h = if h.len() % 2 == 1 {
            format!("0{h}")
        } else {
            h.to_string()
        };
        hex::decode(h).ok()?
    } else {
        decimal_to_be(&s)?
    };
    let bytes = if bytes.len() > 32 {
        let (head, tail) = bytes.split_at(bytes.len() - 32);
        head.iter().all(|b| *b == 0).then_some(tail.to_vec())?
    } else {
        bytes
    };
    field_from_be_bytes_canonical(&bytes, "input").ok()
}

/// Bits needed to write `f` in binary.
fn bit_length(f: &Field) -> u32 {
    let mut bits = 256;
    for b in noir_zk_core::codec::field_to_be_bytes32(f) {
        if b != 0 {
            return bits - b.leading_zeros();
        }
        bits -= 8;
    }
    0
}

/// A decimal string as big-endian bytes.
fn decimal_to_be(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut be: Vec<u8> = vec![0];
    for c in s.bytes() {
        let mut carry = u32::from(c - b'0');
        for b in be.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            be.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    Some(be)
}

fn encode_table(
    fields: &[(String, Type)],
    table: &toml::Table,
    at: &str,
    out: &mut Vec<Field>,
) -> Result<(), Error> {
    let path = |n: &str| {
        if at.is_empty() {
            n.to_string()
        } else {
            format!("{at}.{n}")
        }
    };
    if let Some(extra) = table.keys().find(|k| !fields.iter().any(|(n, _)| n == *k)) {
        return Err(Error::Abi(format!("{}: not a parameter", path(extra))));
    }
    for (name, t) in fields {
        let v = table
            .get(name)
            .ok_or_else(|| Error::Abi(format!("{}: missing", path(name))))?;
        t.encode(v, &path(name), out)?;
    }
    Ok(())
}

/// A circuit's ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abi {
    /// `main`'s parameters in declaration order (witness order).
    pub parameters: Vec<(String, Type)>,
    /// Its return type, if any.
    pub return_type: Option<Type>,
}

impl Abi {
    /// From nargo's ABI JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let v: Value =
            serde_json::from_str(json).map_err(|e| Error::Artifact(format!("ABI: {e}")))?;
        let parameters = v["parameters"]
            .as_array()
            .ok_or_else(|| Error::Artifact("ABI has no parameters".into()))?
            .iter()
            .map(|p| {
                let name = p["name"]
                    .as_str()
                    .ok_or_else(|| Error::Artifact("ABI parameter without a name".into()))?;
                Ok((name.to_string(), Type::from_json(&p["type"])?))
            })
            .collect::<Result<_, Error>>()?;
        let return_type = match v["return_type"].get("abi_type") {
            Some(t) => Some(Type::from_json(t)?),
            None => None,
        };
        Ok(Self {
            parameters,
            return_type,
        })
    }

    /// Field elements of all parameters: the return value's witnesses follow.
    pub fn field_count(&self) -> usize {
        self.parameters.iter().map(|(_, t)| t.field_count()).sum()
    }

    /// Field elements of the return value.
    pub fn return_field_count(&self) -> usize {
        self.return_type.as_ref().map_or(0, Type::field_count)
    }

    /// `Prover.toml` text as field elements in witness order.
    pub fn encode_toml(&self, text: &str) -> Result<Vec<Field>, Error> {
        let table: toml::Table =
            toml::from_str(text).map_err(|e| Error::Abi(format!("Prover.toml: {e}")))?;
        let mut out = Vec::with_capacity(self.field_count());
        encode_table(&self.parameters, &table, "", &mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi() -> Abi {
        Abi::from_json(
            r#"{"parameters": [
                {"name": "x", "type": {"kind": "field"}, "visibility": "private"},
                {"name": "b", "type": {"kind": "array", "length": 2, "type": {"kind": "integer", "sign": "unsigned", "width": 8}}, "visibility": "private"},
                {"name": "s", "type": {"kind": "struct", "path": "m::S", "fields": [
                    {"name": "on", "type": {"kind": "boolean"}},
                    {"name": "v", "type": {"kind": "field"}}
                ]}, "visibility": "public"}
            ], "return_type": {"abi_type": {"kind": "field"}, "visibility": "public"}}"#,
        )
        .unwrap()
    }

    #[test]
    fn encodes_in_witness_order() {
        let f = abi()
            .encode_toml("x = \"0x10\"\nb = [1, \"255\"]\n[s]\non = true\nv = \"12\"\n")
            .unwrap();
        let expect: Vec<Field> = [16u64, 1, 255, 1, 12].map(Field::from).to_vec();
        assert_eq!(f, expect);
        assert_eq!((abi().field_count(), abi().return_field_count()), (5, 1));
    }

    #[test]
    fn rejects_what_does_not_fit() {
        let a = abi();
        let ok = "b = [1, 2]\n[s]\non = true\nv = 1\n";
        assert!(a.encode_toml(&format!("x = 1\n{ok}")).is_ok());
        // out of range integer, missing / extra keys, non-canonical field
        assert!(a
            .encode_toml("x = 1\nb = [1, 256]\n[s]\non = true\nv = 1\n")
            .is_err());
        assert!(a.encode_toml(ok).is_err());
        assert!(a.encode_toml(&format!("x = 1\ny = 2\n{ok}")).is_err());
        let p = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        assert!(a.encode_toml(&format!("x = \"{p}\"\n{ok}")).is_err());
        assert!(a.encode_toml(&format!("x = \"-1\"\n{ok}")).is_err());
    }
}
