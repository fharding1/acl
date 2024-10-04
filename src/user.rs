use crate::commitment::{Commitment};

pub type PublicKey = VerifyingKey;

impl PublicKey {
    pub fn compute_challenge(&self, commitment: &Commitment, prepare_message: &[u8; 32*4]) -> [u8;64] {
        
    }
}
