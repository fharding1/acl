use acl::{SigningKey, ATTRIBUTE_ID_LENGTH, SECRET_KEY_LENGTH};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

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

    //println!("{:?}, {:?}", ss, msg);
    //println!("{:?}", presig);

    let bob = UserAttributes {
        user_id: 1,
        user_type: UserType::Subscriber,
        is_sports_subscriber: true,
        is_tech_subscriber: false,
    };
}
