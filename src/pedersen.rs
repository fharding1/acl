use curve25519_dalek::ristretto::RistrettoPoint;

pub type AttributeGenerators<const N: usize> = [RistrettoPoint; N] 
