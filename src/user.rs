use crate::constants::{gen_h, gen_z};
use crate::errors::UserError;
use crate::signature::Signature;
use crate::signing::{PreSignature, PrepareMessage};
use crate::verifying::{compute_challenge, VerifyingKey};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use group::GroupEncoding;

use rand_core::{CryptoRng, RngCore};

use digest::{generic_array::typenum::U64, Digest};

pub struct UserParameters {
    pub key: VerifyingKey,
}

#[derive(Debug)]
pub struct UserState {
    pub(crate) commitment: RistrettoPoint,
    pub(crate) rnd: Scalar,
    pub(crate) gamma: Scalar,
    pub(crate) xi: RistrettoPoint,
    pub(crate) xi1: RistrettoPoint,
    pub(crate) tau: Scalar,
    pub(crate) t1: Scalar,
    pub(crate) t2: Scalar,
    pub(crate) t3: Scalar,
    pub(crate) t4: Scalar,
    pub(crate) t5: Scalar,
    pub(crate) hashed_message: Vec<u8>,
}

impl TryFrom<&[u8]> for PrepareMessage {
    type Error = UserError;

    fn try_from(bytes: &[u8]) -> Result<PrepareMessage, UserError> {
        Ok(PrepareMessage {
            a: CompressedRistretto::from_slice(&bytes[0..32])?
                .decompress()
                .ok_or(UserError::PointDecompression)?,
            b1: CompressedRistretto::from_slice(&bytes[32..64])?
                .decompress()
                .ok_or(UserError::PointDecompression)?,
            b2: CompressedRistretto::from_slice(&bytes[64..96])?
                .decompress()
                .ok_or(UserError::PointDecompression)?,
            rnd: Scalar::from_bytes_mod_order(
                bytes[96..128].try_into().expect("has incorrect length"),
            ),
        })
    }
}

impl TryFrom<&[u8]> for PreSignature {
    type Error = UserError;

    fn try_from(bytes: &[u8]) -> Result<Self, UserError> {
        Ok(PreSignature {
            c: Scalar::from_canonical_bytes(
                (&bytes[0..32])
                    .try_into()
                    .expect("slice with incorrect length"),
            )
            .into_option()
            .ok_or(UserError::ScalarFormat)?,
            d: Scalar::from_canonical_bytes(
                (&bytes[32..64])
                    .try_into()
                    .expect("slice with incorrect length"),
            )
            .into_option()
            .ok_or(UserError::ScalarFormat)?,
            r: Scalar::from_canonical_bytes(
                (&bytes[64..96])
                    .try_into()
                    .expect("slice with incorrect length"),
            )
            .into_option()
            .ok_or(UserError::ScalarFormat)?,
            s1: Scalar::from_canonical_bytes(
                (&bytes[96..128])
                    .try_into()
                    .expect("slice with incorrect length"),
            )
            .into_option()
            .ok_or(UserError::ScalarFormat)?,
            s2: Scalar::from_canonical_bytes(
                (&bytes[128..160])
                    .try_into()
                    .expect("slice with incorrect length"),
            )
            .into_option()
            .ok_or(UserError::ScalarFormat)?,
        })
    }
}

impl UserParameters {
    pub fn compute_challenge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        commitment: &RistrettoPoint,
        hashed_message: &[u8],
        signer_message: &[u8],
    ) -> Result<(UserState, Vec<u8>), UserError> {
        let prepare_message = PrepareMessage::try_from(signer_message)?;

        if prepare_message.rnd == Scalar::ZERO {
            return Err(UserError::RndZero);
        }

        let z1 = commitment + RistrettoPoint::mul_base(&prepare_message.rnd);
        let gamma = Scalar::random(rng);

        // this is so unlikely that we don't even retry
        if gamma == Scalar::ZERO {
            return Err(UserError::GammaZero);
        }

        let xi = gen_z() * gamma;
        let xi1 = z1 * gamma;
        let xi2 = xi - xi1;
        let tau = Scalar::random(rng);
        let eta = gen_z() * tau;

        let t1 = Scalar::random(rng);
        let t2 = Scalar::random(rng);
        let t3 = Scalar::random(rng);
        let t4 = Scalar::random(rng);
        let t5 = Scalar::random(rng);

        let alpha = prepare_message.a + RistrettoPoint::mul_base(&t1) + self.key.point * t2;
        let beta1 = prepare_message.b1 * gamma + RistrettoPoint::mul_base(&t3) + t4 * xi1;
        let beta2 = prepare_message.b2 * gamma + gen_h() * t5 + t4 * xi2;

        let epsilon = compute_challenge(&xi, &xi1, &alpha, &beta1, &beta2, &eta, &hashed_message);

        let e = epsilon - t2 - t4;

        Ok((
            UserState {
                commitment: commitment.clone(),
                rnd: prepare_message.rnd,
                gamma: gamma,
                xi: xi,
                xi1: xi1,
                tau: tau,
                t1: t1,
                t2: t2,
                t3: t3,
                t4: t4,
                t5: t5,
                hashed_message: (*hashed_message).to_vec(),
            },
            Vec::from(e.to_bytes()),
        ))
    }

    pub fn compute_signature(
        &self,
        user_state: &UserState,
        presignature_bytes: &[u8],
    ) -> Result<(Signature, RistrettoPoint, Scalar, Scalar), UserError> {
        let presignature = PreSignature::try_from(presignature_bytes)?;

        let rho = presignature.r + user_state.t1;
        let omega = presignature.c + user_state.t2;
        let sigma1 = presignature.s1 * user_state.gamma + user_state.t3;
        let sigma2 = presignature.s2 * user_state.gamma + user_state.t5;
        let delta = presignature.d + user_state.t4;
        let mu = user_state.tau - delta * user_state.gamma;

        let signature = Signature {
            xi: user_state.xi,
            rho: rho,
            omega: omega,
            sigma1: sigma1,
            sigma2: sigma2,
            delta: delta,
            mu: mu,
        };

        self.key.verify_prehashed(
            &user_state.hashed_message,
            &user_state.xi1,
            &signature,
        )?;

        Ok((
            signature,
            user_state.gamma * (user_state.commitment + RistrettoPoint::mul_base(&user_state.rnd)),
            user_state.gamma,
            user_state.rnd,
        ))
    }
}
