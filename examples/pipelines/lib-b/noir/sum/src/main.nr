// Family `ext/sum`: continues the count and is bound to the published `n`.
// Record: `[link_in = c, n (bound to slot n), total]`.
fn main(c: Field, n: Field) -> return_data [Field; 3] {
    [c, n, c + n]
}
