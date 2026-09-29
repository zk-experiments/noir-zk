// Family `base/counter` (big variant, n < 2^32): the same record as the small one.
fn main(s: Field, n: u32) -> return_data [Field; 3] {
    [s, s + n as Field, n as Field]
}
