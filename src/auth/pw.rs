use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
    Argon2, Params, Algorithm, Version
};
use crate::errors::{AppError, Result};

fn create_argon2() -> std::result::Result<Argon2<'static>, argon2::Error> {
    let params = Params::new(65536, 3, 4, Some(32))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = create_argon2().map_err(AppError::ArgonError)?;
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(AppError::PasswordHashError)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash).map_err(AppError::PasswordHashError)?;
    let argon2 = create_argon2().map_err(AppError::ArgonError)?;
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AppError::PasswordHashError(e)),
    }
}
