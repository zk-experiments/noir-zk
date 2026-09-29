// Family `base/counter` (small variant, n < 256): continues the seed, leaves the count.
// Record: `[link_in = s, link_out = s + n, n]`.
fn main(s: Field, n: u8) -> return_data [Field; 3] {
    [s, s + n as Field, n as Field]
}
