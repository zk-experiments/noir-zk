//! The values the generated code is made of, as tokens: identifiers, doc
//! attributes, unsuffixed integers and 32-byte arrays.

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

/// An identifier (a circuit label, a field or type name).
pub(crate) fn ident(s: &str) -> Ident {
    Ident::new(s, Span::call_site())
}

/// `/// text`, as the attribute it stands for.
pub(crate) fn doc(text: &str) -> TokenStream {
    let text = format!(" {text}");
    quote!(#[doc = #text])
}

/// An integer literal without a type suffix (`3`, not `3u64`).
pub(crate) fn u64_lit(n: u64) -> Literal {
    Literal::u64_unsuffixed(n)
}

/// An integer literal without a type suffix (`3`, not `3usize`).
pub(crate) fn usize_lit(n: usize) -> Literal {
    Literal::usize_unsuffixed(n)
}

/// A 32-byte array from 64 hex digits (`0x` optional), as `[0x0e, 0xb7, …]`.
pub(crate) fn bytes32(hex: &str) -> TokenStream {
    let h = hex.trim_start_matches("0x");
    assert_eq!(h.len(), 64, "expected 32-byte hex, got {hex}");
    let bytes = (0..32).map(|i| {
        format!("0x{}", &h[2 * i..2 * i + 2])
            .parse::<Literal>()
            .expect("hex byte literal")
    });
    quote!([#(#bytes),*])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_print_as_written() {
        assert_eq!(u64_lit(3).to_string(), "3");
        assert_eq!(usize_lit(7).to_string(), "7");
        let b = bytes32(&format!("0x0e{}", "00".repeat(31))).to_string();
        assert!(b.starts_with("[0x0e , 0x00"), "{b}");
        assert_eq!(doc("text").to_string(), "# [doc = \" text\"]");
    }
}
