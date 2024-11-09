use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Serialize,Deserialize};

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub(crate) xi: RistrettoPoint,
    pub(crate) rho: Scalar,
    pub(crate) omega: Scalar,
    pub(crate) sigma1: Scalar,
    pub(crate) sigma2: Scalar,
    pub(crate) mu: Scalar,
    pub(crate) delta: Scalar,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 32 * 7] {
        [
            self.xi.compress().to_bytes(),
            self.rho.to_bytes(),
            self.omega.to_bytes(),
            self.sigma1.to_bytes(),
            self.sigma2.to_bytes(),
            self.mu.to_bytes(),
            self.delta.to_bytes(),
        ]
        .concat()
        .as_slice()
        .try_into()
        .expect("slice with incorrect length")
    }
}
