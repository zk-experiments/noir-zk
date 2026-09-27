// Knows a square root of `y`: private, pub and private parameters in that
// order (witness order interleaves them), and a pub return value.
fn main(x: Field, y: pub Field, salt: Field) -> pub Field {
    assert(x * x == y);
    x + salt
}
