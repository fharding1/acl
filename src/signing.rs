use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::{clamp_integer, Scalar};

use sha2::{Digest, Sha512};

use rand_core::{CryptoRng, OsRng, RngCore};

use std::fmt::Debug;

use crate::{
    constants::{gen_h, gen_z, SECRET_KEY_LENGTH},
    errors::SigningError,
};

pub type SecretKey = [u8; SECRET_KEY_LENGTH];

// There's not *really* a reason to not just put the secret key as a scalar in
// this struct, except that in the future we might want to do something similar
// to EdDSA, i.e., using part of the secret key as a salt to a hash function.
pub struct SigningKey {
    pub(crate) scalar: Scalar,
}

#[derive(Debug)]
pub struct SignerState {
    d: Scalar,
    s1: Scalar,
    s2: Scalar,
    u: Scalar,
    rnd: Scalar,
}

impl SignerState {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        SignerState {
            d: Scalar::random(rng),
            s1: Scalar::random(rng),
            s2: Scalar::random(rng),
            u: Scalar::random(rng),
            rnd: Scalar::random(rng),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PrepareMessage {
    pub(crate) a: RistrettoPoint,
    pub(crate) b1: RistrettoPoint,
    pub(crate) b2: RistrettoPoint,
    pub(crate) rnd: Scalar,
}

impl PrepareMessage {
    fn to_bytes(&self) -> [u8; 32 * 4] {
        [
            self.a.compress().to_bytes(),
            self.b1.compress().to_bytes(),
            self.b2.compress().to_bytes(),
            self.rnd.to_bytes(),
        ]
        .concat()
        .as_slice()
        .try_into()
        .expect("slice with incorrect length")
    }
}

pub(crate) struct PreSignature {
    pub(crate) c: Scalar,
    pub(crate) d: Scalar,
    pub(crate) r: Scalar,
    pub(crate) s1: Scalar,
    pub(crate) s2: Scalar,
}

impl PreSignature {
    fn to_bytes(&self) -> [u8; 32 * 5] {
        [
            self.c.to_bytes(),
            self.d.to_bytes(),
            self.r.to_bytes(),
            self.s1.to_bytes(),
            self.s2.to_bytes(),
        ]
        .concat()
        .as_slice()
        .try_into()
        .expect("slice with incorrect length")
    }
}

impl SigningKey {
    pub fn from_bytes(secret_key: &SecretKey) -> Self {
        let mut hash = Sha512::new();
        hash.update(secret_key);
        let digest = hash.finalize();

        let mut scalar_bytes: [u8; 32] = [0u8; 32];
        scalar_bytes.copy_from_slice(&digest.as_slice()[00..32]);

        Self {
            scalar: Scalar::from_bytes_mod_order(clamp_integer(scalar_bytes)),
        }
    }

    // prepare generates the first message in the ACL protocol, which the user
    // will use to generate a response
    pub fn prepare(
        &self,
        commitment_bytes: &[u8; 32],
    ) -> Result<(SignerState, [u8; 32 * 4]), SigningError> {
        let state = SignerState::random(&mut OsRng);

        let commitment = CompressedRistretto::from_slice(commitment_bytes)?
            .decompress()
            .ok_or(SigningError::PointDecompression)?;

        let z1 = RistrettoPoint::mul_base(&state.rnd) + commitment;
        let z2 = gen_z() - z1;

        let msg = PrepareMessage {
            a: RistrettoPoint::mul_base(&state.u),
            b1: RistrettoPoint::mul_base(&state.s1) + z1 * state.d,
            b2: gen_h() * state.s2 + z2 * state.d,
            rnd: state.rnd.clone(),
        };

        Ok((state, (&msg).to_bytes()))
    }

    // compute_presignature generates a "presignature" from a challenge, which
    // the user will be able to obtain the final signature from
    pub fn compute_presignature(
        &self,
        state: &SignerState,
        challenge_bytes: &[u8; 32],
    ) -> Result<[u8; 32 * 5], String> {
        let e = Scalar::from_canonical_bytes(*challenge_bytes)
            .into_option()
            .ok_or("unable to parse challenge as scalar")?;

        let c = e - state.d;
        let r = state.u - c * self.scalar;

        Ok((&PreSignature {
            c: c,
            d: state.d.clone(),
            r: r,
            s1: state.s1.clone(),
            s2: state.s2.clone(),
        })
            .to_bytes())
    }
}
