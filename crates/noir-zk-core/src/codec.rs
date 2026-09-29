//! Codec: how typed values fold into BN254 field elements and back.
//!
//! Encoding is fallible: there is no total map from arbitrary 256-bit bytes
//! onto the ~254-bit field, and silently reducing (`mod_order`) would alias
//! distinct byte strings onto one element. [`field_from_be_bytes_canonical`]
//! rejects such values; [`field_from_be_bytes`] reduces and is only for inputs
//! already below the modulus.

use ark_ff::{BigInteger, PrimeField};

use crate::error::Error;
use crate::zk::Field;

/// A value occupying exactly one field element.
pub trait FieldElement {
    /// The element, or [`Error::NonCanonical`] if there is none.
    fn to_field(&self) -> Result<Field, Error>;
}

/// A value expanding into zero or more field elements, in canonical order.
pub trait FieldEncode {
    /// Append this value's elements to `out`.
    fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error>;
}

/// Big-endian bytes as one element, reduced mod the field order. Only for
/// inputs known to be below the modulus (at most 31 bytes, say).
pub fn field_from_be_bytes(bytes: &[u8]) -> Field {
    Field::from_be_bytes_mod_order(bytes)
}

/// Big-endian bytes as one element, rejecting values `>=` the modulus.
pub fn field_from_be_bytes_canonical(bytes: &[u8], what: &'static str) -> Result<Field, Error> {
    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    let repr = <<Field as PrimeField>::BigInt as BigInteger>::from_bits_be(&bits);
    Field::from_bigint(repr).ok_or(Error::NonCanonical(what))
}

/// A field element as a `u64`, or none if it doesn't fit.
pub fn field_to_u64(f: &Field) -> Option<u64> {
    let le = f.into_bigint().to_bytes_le();
    le[8..]
        .iter()
        .all(|b| *b == 0)
        .then(|| u64::from_le_bytes(le[..8].try_into().unwrap_or([0; 8])))
}

/// A field element as 32 big-endian bytes (bb's and the chain's encoding).
pub fn field_to_be_bytes32(f: &Field) -> [u8; 32] {
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// A big-endian `uint256` as `[lo, hi]` 128-bit limbs (total: each limb is
/// below the modulus).
pub fn u256_limbs_be(be32: &[u8; 32]) -> [Field; 2] {
    [
        Field::from_be_bytes_mod_order(&be32[16..32]),
        Field::from_be_bytes_mod_order(&be32[0..16]),
    ]
}

macro_rules! scalar {
    ($($t:ty),*) => {$(
        impl FieldElement for $t {
            fn to_field(&self) -> Result<Field, Error> { Ok(Field::from(*self)) }
        }
        impl FieldEncode for $t {
            fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error> {
                out.push(Field::from(*self));
                Ok(())
            }
        }
    )*};
}
scalar!(u8, u16, u32, u64, u128, bool);

impl FieldElement for Field {
    fn to_field(&self) -> Result<Field, Error> {
        Ok(*self)
    }
}

impl FieldEncode for Field {
    fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error> {
        out.push(*self);
        Ok(())
    }
}

impl<T: FieldEncode, const N: usize> FieldEncode for [T; N] {
    fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error> {
        self.iter().try_for_each(|e| e.encode(out))
    }
}

impl<T: FieldEncode> FieldEncode for [T] {
    fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error> {
        self.iter().try_for_each(|e| e.encode(out))
    }
}

impl<T: FieldEncode> FieldEncode for Vec<T> {
    fn encode(&self, out: &mut Vec<Field>) -> Result<(), Error> {
        self.as_slice().encode(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_checks_ranges_and_length() {
        let f = [Field::from(1u64), Field::from(300u64), Field::from(2u64)];
        let mut r = FieldReader::new(&f);
        assert!(r.boolean().unwrap());
        assert!(r.uint::<u8>(8).is_err());
        assert!(r.boolean().is_err());
        assert!(r.field().is_err());
        let mut r = FieldReader::new(&f);
        r.field().unwrap();
        assert_eq!(r.uint::<u16>(16).unwrap(), 300);
        assert!(r.finish().is_err());
    }

    #[test]
    fn canonical_decode_rejects_the_modulus() {
        let p = Field::MODULUS.to_bytes_be();
        assert_eq!(
            field_from_be_bytes_canonical(&p, "p"),
            Err(Error::NonCanonical("p"))
        );
        let mut below = p.clone();
        *below.last_mut().unwrap() -= 1;
        assert!(field_from_be_bytes_canonical(&below, "p - 1").is_ok());
    }

    #[test]
    fn round_trips_32_byte_encoding() {
        let f = Field::from(0x0102_0304u64);
        let b = field_to_be_bytes32(&f);
        assert_eq!(b[28..], [1, 2, 3, 4]);
        assert_eq!(field_from_be_bytes_canonical(&b, "f").unwrap(), f);
    }

    #[test]
    fn arrays_encode_in_order() {
        let mut out = vec![];
        [[1u8, 2], [3, 4]].encode(&mut out).unwrap();
        assert_eq!(out, [1u64, 2, 3, 4].map(Field::from));
        true.encode(&mut out).unwrap();
        assert_eq!(out.last(), Some(&Field::from(1u64)));
    }

    #[test]
    fn u256_limbs_split_low_first() {
        let mut be = [0u8; 32];
        be[31] = 7;
        be[0] = 9;
        let [lo, hi] = u256_limbs_be(&be);
        assert_eq!(lo, Field::from(7u64));
        assert_eq!(hi, Field::from(9u128 << 120));
    }
}

/// Reads typed values off a flat field-element list (generated `Outputs`
/// decoders use it), rejecting values out of their type's range.
pub struct FieldReader<'a> {
    fields: std::slice::Iter<'a, Field>,
}

impl<'a> FieldReader<'a> {
    /// Reads `fields` from the start.
    pub fn new(fields: &'a [Field]) -> Self {
        Self {
            fields: fields.iter(),
        }
    }

    /// The next field element.
    pub fn field(&mut self) -> Result<Field, Error> {
        self.fields
            .next()
            .copied()
            .ok_or_else(|| Error::Abi("too few returned fields".into()))
    }

    /// The next element as a boolean (0 or 1).
    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.uint::<u8>(1)? {
            0 => Ok(false),
            _ => Ok(true),
        }
    }

    /// The next element as an unsigned integer of `bits` bits.
    pub fn uint<T: TryFrom<u128>>(&mut self, bits: u32) -> Result<T, Error> {
        let be = field_to_be_bytes32(&self.field()?);
        let v = if be[..16].iter().any(|b| *b != 0) {
            None
        } else {
            let mut lo = [0u8; 16];
            lo.copy_from_slice(&be[16..]);
            Some(u128::from_be_bytes(lo)).filter(|v| bits >= 128 || v >> bits == 0)
        };
        v.and_then(|v| T::try_from(v).ok())
            .ok_or_else(|| Error::Abi(format!("returned value exceeds {bits} bits")))
    }

    /// Fails unless every field was read.
    pub fn finish(mut self) -> Result<(), Error> {
        match self.fields.next() {
            None => Ok(()),
            Some(_) => Err(Error::Abi("too many returned fields".into())),
        }
    }
}

/// A value decoded from field elements in ABI order (return values, witness
/// structs). Implemented for fields, booleans, unsigned integers, arrays and
/// every generated struct.
pub trait FromFields: Sized {
    /// Field elements the value spans.
    const FIELDS: usize;
    /// Reads the value off `r`.
    fn read(r: &mut FieldReader<'_>) -> Result<Self, Error>;
}

/// Decodes exactly `fields` as a `T`.
pub fn from_fields<T: FromFields>(fields: &[Field]) -> Result<T, Error> {
    let mut r = FieldReader::new(fields);
    let v = T::read(&mut r)?;
    r.finish()?;
    Ok(v)
}

impl FromFields for () {
    const FIELDS: usize = 0;
    fn read(_: &mut FieldReader<'_>) -> Result<Self, Error> {
        Ok(())
    }
}

impl FromFields for Field {
    const FIELDS: usize = 1;
    fn read(r: &mut FieldReader<'_>) -> Result<Self, Error> {
        r.field()
    }
}

impl FromFields for bool {
    const FIELDS: usize = 1;
    fn read(r: &mut FieldReader<'_>) -> Result<Self, Error> {
        r.boolean()
    }
}

macro_rules! uint_from_fields {
    ($($t:ty),*) => {$(
        impl FromFields for $t {
            const FIELDS: usize = 1;
            fn read(r: &mut FieldReader<'_>) -> Result<Self, Error> {
                r.uint(<$t>::BITS)
            }
        }
    )*};
}
uint_from_fields!(u8, u16, u32, u64, u128);

impl<T: FromFields, const N: usize> FromFields for [T; N] {
    const FIELDS: usize = N * T::FIELDS;
    fn read(r: &mut FieldReader<'_>) -> Result<Self, Error> {
        let v = (0..N).map(|_| T::read(r)).collect::<Result<Vec<T>, _>>()?;
        v.try_into().map_err(|_| Error::Abi("array length".into()))
    }
}
