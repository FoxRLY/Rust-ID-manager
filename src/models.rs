use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(FromRow, Serialize, Deserialize)]
pub struct UserId {
    pub id: i32,
}

#[derive(FromRow, Serialize, Deserialize)]
pub struct UserInfoOut {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
}

#[derive(FromRow)]
pub struct AuthenticationVerifier {
    pub id: i32,
    pub password: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserInfoIn {
    pub name: String,
    pub email: String,
    pub role: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationInfo {
    pub email: String,
    pub password: String,
}
