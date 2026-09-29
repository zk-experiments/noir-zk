//! kernel_tail: folds the last kernel (no app) and passes the state on
//! unchanged: padding for a one-app pipeline (Chonk folds at least four circuits).
use pipeline_kernel::{check_vk, PROOF_TYPE_HN, ROLE_KERNEL, S_PIPELINE_ROOT, STATE_FIELDS, Vk};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    prev_vk: Vk,
) -> return_data [Field; STATE_FIELDS] {
    let h = check_vk(prev[S_PIPELINE_ROOT], ROLE_KERNEL, 0, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], h, PROOF_TYPE_HN);
    prev
}
