use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SigningError {
    CompressedPointFormat,
    PointDecompression,
    ScalarFormat,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SigningError::CompressedPointFormat => {
                write!(f, "Compressed Ristretto point is incorrectly formatted")
            }
            SigningError::PointDecompression => write!(f, "Cannot decompress Ristretto point"),
            SigningError::ScalarFormat => write!(f, "Scalar is not canonically formatted"),
        }
    }
}

impl Error for SigningError {}

impl From<TryFromSliceError> for SigningError {
    fn from(_: TryFromSliceError) -> SigningError {
        SigningError::CompressedPointFormat
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum VerifyingError {
    CompressedPointFormat,
    PointDecompression,
    Invalid,
    ScalarFormat,
}

impl Display for VerifyingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            VerifyingError::CompressedPointFormat => {
                write!(f, "Compressed Ristretto point is incorrectly formatted")
            }
            VerifyingError::PointDecompression => write!(f, "Cannot decompress Ristretto point"),
            VerifyingError::Invalid => write!(f, "Signature is invalid"),
            VerifyingError::ScalarFormat => write!(f, "Scalar is not canonically formatted"),
        }
    }
}

impl Error for VerifyingError {}

impl From<TryFromSliceError> for VerifyingError {
    fn from(_: TryFromSliceError) -> VerifyingError {
        VerifyingError::CompressedPointFormat
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UserError {
    CompressedPointFormat,
    PointDecompression,
    RndZero,
    ScalarFormat,
    GammaZero,
    Invalid { err: VerifyingError },
}

impl Error for UserError {}

impl From<VerifyingError> for UserError {
    fn from(err: VerifyingError) -> UserError {
        UserError::Invalid { err }
    }
}

impl Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            UserError::CompressedPointFormat => {
                write!(f, "Compressed Ristretto point is incorrectly formatted")
            }
            UserError::PointDecompression => write!(f, "Cannot decompress Ristretto point"),
            UserError::RndZero => write!(f, "Signer did not generate a non-zero value for rnd"),
            UserError::ScalarFormat => write!(f, "Scalar is not canonically formatted"),
            UserError::GammaZero => write!(f, "Accidentally generated a zero value for gamma"),
            UserError::Invalid { err } => write!(f, "Invalid signature: {}", err),
        }
    }
}

impl From<TryFromSliceError> for UserError {
    fn from(_: TryFromSliceError) -> UserError {
        UserError::CompressedPointFormat
    }
}
