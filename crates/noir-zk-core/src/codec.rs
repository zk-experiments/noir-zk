//! Codec: how typed values fold into BN254 field elements and back, ported
//! from `pso-protocol`'s field encoding.
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
