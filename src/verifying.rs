use crate::constants::{gen_h, gen_z};
use crate::errors::VerifyingError;
use crate::signature::Signature;
use crate::signing::SigningKey;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::{generic_array::typenum::U64, Digest};
use sha2::Sha512;

#[derive(Copy, Clone, Default)]
pub struct VerifyingKey {
    pub(crate) point: RistrettoPoint,
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> VerifyingKey {
        VerifyingKey {
            point: RistrettoPoint::mul_base(&signing_key.scalar),
        }
    }
}

impl VerifyingKey {
    fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
}

impl TryFrom<&[u8; 32]> for VerifyingKey {
    type Error = VerifyingError;

    fn try_from(bytes: &[u8; 32]) -> Result<VerifyingKey, VerifyingError> {
        Ok(VerifyingKey { point: CompressedRistretto::from_slice(bytes)?.decompress().ok_or(VerifyingError::KeyFormat)? })
    }
}


pub(crate) fn compute_challenge(
    xi: &RistrettoPoint,
    xi1: &RistrettoPoint,
    alpha: &RistrettoPoint,
    beta1: &RistrettoPoint,
    beta2: &RistrettoPoint,
    eta: &RistrettoPoint,
    hashed_message: &[u8; 64],
) -> Scalar {
    let mut hash = Sha512::new();
    
    hash.update(xi.compress().to_bytes());
    hash.update(xi1.compress().to_bytes());
    hash.update(alpha.compress().to_bytes());
    hash.update(beta1.compress().to_bytes());
    hash.update(beta2.compress().to_bytes());
    hash.update(eta.compress().to_bytes());
    hash.update(hashed_message);

    Scalar::from_bytes_mod_order_wide(hash.finalize().as_ref())
}

impl VerifyingKey {
    pub fn verify_prehashed(
        &self,
        hashed_message: &[u8; 64],
        commitment: &RistrettoPoint,
        sig: &Signature,
    ) -> Result<(), VerifyingError> {
        let check = compute_challenge(
            &sig.xi,
            &commitment,
            &(RistrettoPoint::mul_base(&sig.rho) + self.point * sig.omega),
            &(RistrettoPoint::mul_base(&sig.sigma1) + commitment * sig.delta),
            &(sig.sigma2 * gen_h() + (sig.xi - commitment) * sig.delta),
            &(sig.mu * gen_z() + sig.xi * sig.delta),
            hashed_message,
        );

        if check == sig.omega + sig.delta {
            Ok(())
        } else {
            Err(VerifyingError::Invalid)
        }
    }
}
