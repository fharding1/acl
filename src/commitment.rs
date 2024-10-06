use crate::constants::{gen_h, ATTRIBUTE_ID_LENGTH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

pub type AttributeIdentifier = [u8; ATTRIBUTE_ID_LENGTH];
pub type Attribute = u128;

#[derive(Debug,Clone)]
pub struct GeneralizedPedersenCommitment<const N: usize> {
    randomness: [u8; 32],
    attribute_ids: [AttributeIdentifier; N],
    attributes: [Attribute; N],
}

pub fn commit<R: RngCore + CryptoRng, const N: usize>(
    mut rng: R,
    attribute_ids: [AttributeIdentifier; N],
    attributes: [Attribute; N],
) -> GeneralizedPedersenCommitment<N> {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    GeneralizedPedersenCommitment::<N> {
        randomness: bytes,
        attribute_ids: attribute_ids,
        attributes: attributes,
    }
}

impl<const N: usize> GeneralizedPedersenCommitment<N> {
    pub fn to_bytes(&self) -> [u8; 32] {
        RistrettoPoint::from(self).compress().to_bytes()
    }
}

impl<const N: usize> From<&GeneralizedPedersenCommitment<N>> for RistrettoPoint {
    fn from(commitment: &GeneralizedPedersenCommitment<N>) -> RistrettoPoint {
        let mut point =
            gen_h() * Scalar::from_bytes_mod_order(clamp_integer(commitment.randomness));

        for i in 1..N {
            let generator = RistrettoPoint::hash_from_bytes::<Sha512>(&commitment.attribute_ids[i]);
            point = point + generator * Scalar::from(commitment.attributes[i]);
        }

        point
    }
}

#[derive(Clone,Debug)]
pub struct BlindedCommitment<const N: usize> {
    pub(crate) gamma: [u8; 32],
    pub(crate) rnd: [u8; 32],
    pub(crate) commitment: GeneralizedPedersenCommitment<N>,
}

impl<const N: usize> BlindedCommitment<N> {
    pub fn to_bytes(&self) -> [u8; 32] {
        RistrettoPoint::from(self).compress().to_bytes()
    }
}

impl<const N: usize> From<&BlindedCommitment<N>> for RistrettoPoint {
    fn from(blinded_commitment: &BlindedCommitment<N>) -> RistrettoPoint {
        let rnd = Scalar::from_bytes_mod_order(blinded_commitment.rnd);
        let gamma = Scalar::from_bytes_mod_order(blinded_commitment.gamma);

        gamma
            * (RistrettoPoint::from(&blinded_commitment.commitment)
                + RistrettoPoint::mul_base(&rnd))
    }
}
