use acl::{SigningKey, SECRET_KEY_LENGTH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;

fn main() {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let (ss, msg) = signing_key.prepare(&[0u8; 32]).expect("this should fail");
    let presig = signing_key.compute_presignature(&ss, &[0u8; 32]);

    println!("{:?}, {:?}", ss, msg);
    println!("{:?}", presig);
}
