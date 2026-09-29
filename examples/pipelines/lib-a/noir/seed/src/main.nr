// Family `base/seed`: starts a chain from a secret seed. Record: `[link_out = s, seed_sq]`.
fn main(s: Field) -> return_data [Field; 2] {
    [s, s * s]
}
