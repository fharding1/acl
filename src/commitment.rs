use crate::constants::{gen_h, ATTRIBUTE_ID_LENGTH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

pub type AttributeIdentifier = [u8; ATTRIBUTE_ID_LENGTH];
pub type Attribute = u128;

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

impl<const N: usize> GeneralizedPedersenCommitment::<N> {
    pub fn to_bytes(&self) -> [u8; 32] {
        RistrettoPoint::from(self).compress().to_bytes()
    }
}

impl<const N: usize> From<&GeneralizedPedersenCommitment<N>> for RistrettoPoint {
    fn from(cmt: &GeneralizedPedersenCommitment<N>) -> RistrettoPoint {
        let mut point = gen_h() * Scalar::from_bytes_mod_order(clamp_integer(cmt.randomness));

        for i in 1..N {
            let generator = RistrettoPoint::hash_from_bytes::<Sha512>(&cmt.attribute_ids[i]);
            point = point + generator * Scalar::from(cmt.attributes[i]);
        }

        point
    }
}

pub struct BlindedCommitment<const N: usize> {
    gamma: [u8; 32],
    rnd: [u8; 32],
    cmt: GeneralizedPedersenCommitment<N>,
}
