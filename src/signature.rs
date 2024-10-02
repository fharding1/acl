use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature {
    pub(crate) xi: RistrettoPoint,
    pub(crate) rho: Scalar,
    pub(crate) omega: Scalar,
    pub(crate) rho1_prime: Scalar,
    pub(crate) rho2_prime: Scalar,
    pub(crate) omega_prime: Scalar,
    pub(crate) mu: Scalar,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 32*7] {
        [
            self.xi.compress().to_bytes(),
            self.rho.to_bytes(),
            self.omega.to_bytes(),
            self.rho1_prime.to_bytes(),
            self.rho2_prime.to_bytes(),
            self.omega_prime.to_bytes(),
            self.mu.to_bytes(),
        ]
            .concat()
            .as_slice()
            .try_into()
            .expect("slice with incorrect length")
    }
}
