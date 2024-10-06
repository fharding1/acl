mod commitment;
mod constants;
mod errors;
mod signature;
mod signing;
mod user;
mod verifying;

pub use crate::commitment::*;
pub use crate::constants::*;
pub use crate::errors::*;
pub use crate::signature::*;
pub use crate::signing::*;
pub use crate::user::*;
pub use crate::verifying::*;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
