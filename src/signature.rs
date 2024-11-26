use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Serialize,Deserialize};

#[derive(Copy, Clone, Eq,Debug, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub xi: RistrettoPoint,
    pub rho: Scalar,
    pub omega: Scalar,
    pub sigma1: Scalar,
    pub sigma2: Scalar,
    pub mu: Scalar,
    pub delta: Scalar,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
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
    }
}
