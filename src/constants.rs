use std::sync::OnceLock;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;

pub const SECRET_KEY_LENGTH: usize = 32;

// nothing-up-my-sleeve generation of another generator as H=SHA512(G)
// TODO: should probably be pub(crate)
pub fn gen_h() -> &'static RistrettoPoint {
    static GENERATOR_H: OnceLock<RistrettoPoint> = OnceLock::new();

    GENERATOR_H.get_or_init(|| {
        RistrettoPoint::hash_from_bytes::<Sha512>(
            RistrettoPoint::mul_base(&Scalar::ONE).compress().as_bytes(),
        )
    })
}

// nothing-up-my-sleeve generation of another generator as Z=SHA512(H)=SHA512(SHA512(G))
pub fn gen_z() -> &'static RistrettoPoint {
    static GENERATOR_Z: OnceLock<RistrettoPoint> = OnceLock::new();

    GENERATOR_Z
        .get_or_init(|| RistrettoPoint::hash_from_bytes::<Sha512>(gen_h().compress().as_bytes()))
}
