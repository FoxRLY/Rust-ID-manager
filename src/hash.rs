use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::error::Error;

pub struct HashedPassword {
    pub hash: String,
    pub salt: String,
}

fn hash_with_salt(password: &[u8], salt: &SaltString) -> Result<HashedPassword, Box<dyn Error>> {
    let hashed_password = Argon2::default()
        .hash_password(password, salt)
        .map_err(|_| "Hashing failed")?;
    Argon2::default()
        .verify_password(password, &hashed_password)
        .map_err(|_| "Hash verification failed")?;

    let h = hashed_password
        .hash
        .ok_or("Hash is not obtainable")?
        .to_string();
    let s = hashed_password
        .salt
        .ok_or("Salt is not obtainable")?
        .to_string();
    return Ok(HashedPassword { hash: h, salt: s });
}

pub fn hash(password: &str) -> Result<HashedPassword, Box<dyn Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let password = password.as_bytes();
    hash_with_salt(password, &salt)
}

pub fn verify(password: &str, hashed_password: &str, salt: &str) -> Result<(), Box<dyn Error>> {
    // Переводим пароль из строки в байты
    let password = password.as_bytes();

    // Переводим соль из строки в байты
    let salt_b = SaltString::from_b64(&salt).map_err(|_| "Error decoding b64 salt")?;

    let new_hash = hash_with_salt(password, &salt_b).map_err(|_| "Error during hashing")?;

    // Если хэш и соль совпадают с теми, что хранятся в базе, значит
    // пароли совпадают
    if (new_hash.hash == hashed_password) && (new_hash.salt == salt) {
        Ok(())
    } else {
        Err("Password is not correct".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_working() {
        let password = "Super Duper Password 1337";
        let hash = hash(password).unwrap();
        assert!(verify(password, &hash.hash, &hash.salt).is_ok());
    }
}
