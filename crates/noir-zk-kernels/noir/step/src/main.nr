//! kernel_step: folds the previous kernel and the app at the state's
//! position, and applies the app's layout to the state.
use pipeline_kernel::{
    apply, check_vk, Layout, PROOF_TYPE_HN, R, ROLE_KERNEL, S_PIPELINE_ROOT, S_POSITION,
    STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    step: call_data(1) [Field; R],
    prev_vk: Vk,
    step_vk: Vk,
    layout: Layout,
) -> return_data [Field; STATE_FIELDS] {
    let root = prev[S_PIPELINE_ROOT];
    let hk = check_vk(root, ROLE_KERNEL, 0, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], hk, PROOF_TYPE_HN);
    let hs = check_vk(root, prev[S_POSITION], layout.hash(), step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], hs, PROOF_TYPE_HN);
    apply(prev, step, layout)
}
