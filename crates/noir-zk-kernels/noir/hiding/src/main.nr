//! kernel_hiding: folds the last kernel (Chonk's final zero-knowledge step),
//! proves the pipeline root is a leaf of the deployment tree, and publishes
//! the deployment root, the pipeline root, the length and the slots.
use pipeline_kernel::{
    check_vk, DEPLOYMENT_HEIGHT, merkle_root, MerklePath, P, PROOF_TYPE_HN_FINAL, PublicOutputs,
    ROLE_KERNEL, S_PIPELINE_ROOT, S_POSITION, S_SLOTS, STATE_FIELDS, Vk,
};

fn main(
    prev: call_data(0) [Field; STATE_FIELDS],
    prev_vk: Vk,
    deployment: MerklePath<DEPLOYMENT_HEIGHT>,
) -> pub PublicOutputs {
    let h = check_vk(prev[S_PIPELINE_ROOT], ROLE_KERNEL, 0, prev_vk);
    std::verify_proof_with_type(prev_vk.key, [], [], h, PROOF_TYPE_HN_FINAL);
    let mut slots: [Field; P] = [0; P];
    for i in 0..P {
        slots[i] = prev[S_SLOTS + i];
    }
    PublicOutputs {
        deployment_root: merkle_root(prev[S_PIPELINE_ROOT], deployment),
        pipeline_root: prev[S_PIPELINE_ROOT],
        length: prev[S_POSITION],
        slots,
    }
}
