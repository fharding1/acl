use acl::{
    SigningKey, UserParameters, VerifyingKey,SECRET_KEY_LENGTH, gen_h,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::GroupEncoding;

use rand_core::OsRng;

use sha2::Sha512;

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum UserType {
    Free = 1,
    Subscriber = 2,
    Administrator = 64,
}

struct UserAttributes {
    user_id: u128,
    user_type: UserType,
    is_sports_subscriber: bool,
    is_tech_subscriber: bool,
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum UserAttributeID {
    UserID = 1,
    Type = 2,
    Sports = 3,
    Tech = 4,
}

impl UserAttributeID {
    fn as_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0] = *self as u8;
        buf
    }
}

fn main() {
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
        157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
        197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
    ];

    let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

    let (ss, msg) = signing_key.prepare(&[0u8; 32]).expect("this should fail");
    let presig = signing_key.compute_presignature(&ss, &[0u8; 32]);

    let bob = UserAttributes {
        user_id: 1,
        user_type: UserType::Subscriber,
        is_sports_subscriber: true,
        is_tech_subscriber: false,
    };

    let attribute_ids = [
        UserAttributeID::UserID.as_bytes(),
        UserAttributeID::Type.as_bytes(),
        UserAttributeID::Sports.as_bytes(),
        UserAttributeID::Tech.as_bytes(),
    ];

    let generators: Vec<RistrettoPoint> = attribute_ids.into_iter().map(|id| RistrettoPoint::hash_from_bytes::<Sha512>(&id)).collect();

    let commitment = gen_h() * Scalar::random(&mut OsRng) + generators[0] * Scalar::from(bob.user_id) + generators[1] * Scalar::from(bob.user_type as u128) + generators[2] * Scalar::from(bob.is_sports_subscriber as u128) + generators[3] * Scalar::from(bob.is_tech_subscriber as u128);

    let commit_bytes = commitment.compress().to_bytes();

    let (ss, prepare_message) = signing_key
        .prepare(&commit_bytes)
        .expect("this should work");

    let user_params = UserParameters {
        key: VerifyingKey::from(&signing_key),
    };

    let (us, challenge) = user_params
        .compute_challenge(&mut OsRng, &commitment, &[0u8; 64], &prepare_message)
        .expect("this should work");

    let presignature = signing_key
        .compute_presignature(&ss, &challenge)
        .expect("should work");

    let (signature, blinded_commitment, gamma, rnd) = user_params
        .compute_signature(&us, &presignature)
        .expect("sig should be fine");

    println!("valid: {:?}", user_params.key.verify_prehashed(&[0u8; 64], &blinded_commitment.to_bytes(), &signature));
    println!("valid: {:?}", user_params.key.verify_prehashed(&[1u8; 64], &blinded_commitment.to_bytes(), &signature));
}
