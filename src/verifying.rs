use crate::errors::VerifyingError;
use crate::signature::Signature;
use crate::signing::ExpandedSecretKey;
use crate::constants::{gen_h,gen_z};
use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
use curve25519_dalek::scalar::{Scalar};
use digest::{generic_array::typenum::U64, Digest};
use sha2::Sha512;

use std::fmt::Debug;

#[derive(Copy, Clone, Default)]
pub struct VerifyingKey {
    pub(crate) point: RistrettoPoint,
}

impl From<&ExpandedSecretKey> for VerifyingKey {
    fn from(secret_key: &ExpandedSecretKey) -> VerifyingKey {
        VerifyingKey {
            point: RistrettoPoint::mul_base(&secret_key.scalar),
        }
    }
}

impl VerifyingKey {
    pub(crate) fn verify_prehashed<MsgDigest>(
        &self,
        prehashed_message: MsgDigest,
        commitment_bytes: &[u8; 32],
        sig: &Signature,
    ) -> Result<(), VerifyingError>
    where
        MsgDigest: Digest<OutputSize = U64>,
    {
        let commitment = CompressedRistretto::from_slice(commitment_bytes)?
            .decompress()
            .ok_or(VerifyingError::PointDecompression)?;

        let mut hash = Sha512::new();
        hash.update(sig.xi.compress().to_bytes());
        hash.update(commitment_bytes);
        hash.update((RistrettoPoint::mul_base(&sig.rho) + self.point * sig.omega).compress().to_bytes());
        hash.update((RistrettoPoint::mul_base(&sig.rho1_prime) + commitment * sig.omega_prime).compress().to_bytes());
        hash.update((sig.rho2_prime * gen_h() + (commitment - sig.xi) * sig.omega_prime).compress().to_bytes());
        hash.update((sig.mu * gen_z() + commitment * sig.omega_prime).compress().to_bytes());
        hash.update(prehashed_message.finalize());

        let check = Scalar::from_bytes_mod_order_wide(hash.finalize().as_ref());

        if check == sig.omega + sig.omega_prime { Ok(()) } else { Err(VerifyingError::Invalid) }
    }
}
