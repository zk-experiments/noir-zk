//! kernel_init: folds the pipeline's first app (OINK) and starts the state
//! from the pipeline root the prover supplies (the hiding kernel proves it is
//! in the deployment tree).
use pipeline_kernel::{
    apply, check_vk, Layout, PROOF_TYPE_OINK, R, S_PIPELINE_ROOT, STATE_FIELDS, Vk,
};

fn main(
    step: call_data(1) [Field; R],
    step_vk: Vk,
    layout: Layout,
    vk_tree_root: Field,
) -> return_data [Field; STATE_FIELDS] {
    let h = check_vk(vk_tree_root, 0, layout.hash(), step_vk);
    std::verify_proof_with_type(step_vk.key, [], [], h, PROOF_TYPE_OINK);
    let mut s: [Field; STATE_FIELDS] = [0; STATE_FIELDS];
    s[S_PIPELINE_ROOT] = vk_tree_root;
    apply(s, step, layout)
}
