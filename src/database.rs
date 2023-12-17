use crate::hash::{hash, verify};
use crate::models::{AuthenticationInfo, AuthenticationVerifier, UserId, UserInfoIn, UserInfoOut};
use async_trait::async_trait;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, Postgres};
use sqlx::{FromRow, Pool};
use std::env;
use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum DBError {
    QueryError(Box<dyn Error>),
    LogicError(Box<dyn Error>),
    OtherError(Box<dyn Error>),
}

impl Display for DBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DBError::LogicError(e) => {
                write!(f, "Logic error: {e}")
            }
            DBError::QueryError(e) => {
                write!(f, "Query error: {e}")
            }
            DBError::OtherError(e) => {
                write!(f, "Other error: {e}")
            }
        }
    }
}

type DBResult<T> = Result<T, DBError>;

#[async_trait]
pub trait DBClient: Send + Sync {
    async fn init_db(&self) -> DBResult<()>;
    async fn init_db_clear(&self) -> DBResult<()>;
    async fn get_all_users(&self) -> DBResult<Vec<UserInfoOut>>;
    async fn check_user_registration(&self, auth_info: AuthenticationInfo)
        -> DBResult<Option<i32>>;
    async fn add_user(&self, new_user: UserInfoIn) -> DBResult<UserId>;
    async fn remove_user(&self, user_id: i32) -> DBResult<()>;
    async fn change_user_name(&self, user_id: i32, new_name: String) -> DBResult<()>;
    async fn change_user_email(&self, user_id: i32, new_email: String) -> DBResult<()>;
    async fn change_user_role(&self, user_id: i32, new_role: String) -> DBResult<()>;
    async fn change_user_password(&self, user_id: i32, new_password: String) -> DBResult<()>;
}

pub struct DBCLientPostgres {
    inner_client: Pool<Postgres>,
}

impl DBCLientPostgres {
    pub async fn new() -> DBResult<Self> {
        let options = PgConnectOptions::new()
            .host(&env::var("DB_CONTAINER_NAME").unwrap_or("localhost".to_owned()))
            .username(&env::var("DB_USERNAME").unwrap_or("username".to_owned()))
            .password(&env::var("DB_PASSWORD").unwrap_or("password".to_owned()))
            .database(&env::var("DB_NAME").unwrap_or("username".to_owned()))
            .port(5432);
        let client = PgPoolOptions::new()
            .max_connections(7)
            .connect_with(options)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let client = DBCLientPostgres {inner_client: client};
        client.init_db().await?;
        Ok(client)
    }

    pub async fn new_test() -> DBResult<Self> {
        let options = PgConnectOptions::new()
            .host(&env::var("DB_TEST_CONTAINER_NAME").unwrap_or("localhost".to_owned()))
            .username(&env::var("DB_USERNAME").unwrap_or("username".to_owned()))
            .password(&env::var("DB_PASSWORD").unwrap_or("password".to_owned()))
            .database(&env::var("DB_NAME").unwrap_or("username".to_owned()))
            .port(5432);
        let client = PgPoolOptions::new()
            .max_connections(7)
            .connect_with(options)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let client = DBCLientPostgres {inner_client: client};
        client.init_db_clear().await?;
        Ok(client)
    }
}

#[async_trait]
impl DBClient for DBCLientPostgres {
    async fn init_db(&self) -> DBResult<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        role VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        salt VARCHAR(255) NOT NULL
                    )"#,
        )
        .execute(&self.inner_client)
        .await
        .map_err(|e| DBError::QueryError(e.into()))?;
        DBResult::Ok(())
    }

    async fn init_db_clear(&self) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        role VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        salt VARCHAR(255) NOT NULL
                    )"#,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| DBError::QueryError(e.into()))?;

        sqlx::query(r#"TRUNCATE TABLE users"#)
            .execute(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;

        tx.commit()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        DBResult::Ok(())
    }

    async fn get_all_users(&self) -> DBResult<Vec<UserInfoOut>> {
        let all_users: Result<Vec<UserInfoOut>, _> =
            sqlx::query("SELECT id, name, email, role FROM users")
                .fetch_all(&self.inner_client)
                .await
                .map_err(|e| DBError::QueryError(e.into()))?
                .into_iter()
                .map(|row| UserInfoOut::from_row(&row))
                .collect();
        Ok(all_users.map_err(|e| DBError::OtherError(e.into()))?)
    }
    

    /// Проверка данных пользователя при входе
    ///
    /// Проверяет соответствие почты и хэша пароля пользователя с теми, что находятся в базе
    /// Если всё хорошо, то выдаем ID пользователя
    async fn check_user_registration(
        &self,
        auth_info: AuthenticationInfo,
    ) -> DBResult<Option<i32>> {
        let user_record = sqlx::query("SELECT id, password, salt FROM users WHERE email = $1")
            .bind(auth_info.email)
            .fetch_optional(&self.inner_client)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?
            .ok_or(DBError::LogicError("Email is not valid".into()))?;
        let user_record = AuthenticationVerifier::from_row(&user_record)
            .map_err(|e| DBError::OtherError(e.into()))?;

        let verification_result = verify(
            &auth_info.password,
            &user_record.password,
            &user_record.salt,
        );
        if let Ok(_) = verification_result {
            Ok(Some(user_record.id))
        } else {
            Ok(None)
        }
    }

    /// Добавление пользователя в систему
    /// 
    /// При успешной регистрации пользователя возвращается его ID
    /// Если email нового пользователя уже есть в базе, то выводится ошибка
    async fn add_user(&self, new_user: UserInfoIn) -> DBResult<UserId> {
        // Начинаем транзакцию
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        // Проверяем, есть ли пользователь с такой же почтой
        let is_email_present = sqlx::query(r#"SELECT email FROM users WHERE email = $1"#)
            .bind(&new_user.email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?
            .is_some();
        // Если есть, то выдаем ошибку
        if is_email_present {
            Err(DBError::LogicError(
                "User with same email already exists".into(),
            ))?
        }
        // Хэшируем пароль пользователя и получаем пару (хэш, соль)
        let hashed_password =
            hash(&new_user.password).map_err(|e| DBError::OtherError(e.into()))?;
        // Записываем в базу данные о пользователе
        sqlx::query(
            r#"INSERT INTO users(name, email, role, password, salt)
                             VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(new_user.name)
        .bind(&new_user.email)
        .bind(new_user.role)
        .bind(hashed_password.hash)
        .bind(hashed_password.salt)
        .execute(&mut *tx)
        .await
        .map_err(|e| DBError::QueryError(e.into()))?;
        // Получаем id нового пользователя
        let user_id = sqlx::query(r#"SELECT id FROM users WHERE email = $1"#)
            .bind(new_user.email)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let user_id = UserId::from_row(&user_id).map_err(|e| DBError::OtherError(e.into()))?;
        // Завершаем транзакцию
        tx.commit()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        // Возвращаем id нового пользователя
        Ok(user_id)
    }

    async fn remove_user(&self, user_id: i32) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let deleted_user = sqlx::query("DELETE FROM users WHERE id = $1 RETURNING id")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let deleted_user = deleted_user.ok_or(DBError::LogicError("Invalid user ID".into()))?;
        let deleted_user =
            UserId::from_row(&deleted_user).map_err(|e| DBError::OtherError(e.into()))?;
        if deleted_user.id == user_id {
            tx.commit()
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
            Ok(())
        } else {
            Err(DBError::OtherError("IDs are not equal".into()))
        }
    }

    async fn change_user_name(&self, user_id: i32, new_name: String) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = sqlx::query("UPDATE users SET name = $1 WHERE id = $2 RETURNING id")
            .bind(new_name)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = updated_user.ok_or(DBError::LogicError("Invalid user ID".into()))?;
        let updated_user =
            UserId::from_row(&updated_user).map_err(|e| DBError::OtherError(e.into()))?;
        if updated_user.id == user_id {
            tx.commit()
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
            Ok(())
        } else {
            Err(DBError::OtherError("IDs are not equal".into()))
        }
    }

    async fn change_user_email(&self, user_id: i32, new_email: String) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = sqlx::query("UPDATE users SET email = $1 WHERE id = $2 RETURNING id")
            .bind(new_email)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = updated_user.ok_or(DBError::LogicError("Invalid user ID".into()))?;
        let updated_user =
            UserId::from_row(&updated_user).map_err(|e| DBError::OtherError(e.into()))?;
        if updated_user.id == user_id {
            tx.commit()
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
            Ok(())
        } else {
            Err(DBError::OtherError("IDs are not equal".into()))
        }
    }

    async fn change_user_role(&self, user_id: i32, new_role: String) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = sqlx::query("UPDATE users SET role = $1 WHERE id = $2 RETURNING id")
            .bind(new_role)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = updated_user.ok_or(DBError::LogicError("Invalid user ID".into()))?;
        let updated_user =
            UserId::from_row(&updated_user).map_err(|e| DBError::OtherError(e.into()))?;
        if updated_user.id == user_id {
            tx.commit()
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
            Ok(())
        } else {
            Err(DBError::OtherError("IDs are not equal".into()))
        }
    }
    async fn change_user_password(&self, user_id: i32, new_password: String) -> DBResult<()> {
        let mut tx = self
            .inner_client
            .begin()
            .await
            .map_err(|e| DBError::QueryError(e.into()))?;
        let hashed_password = hash(&new_password).map_err(|e| DBError::OtherError(e.into()))?;
        let updated_user =
            sqlx::query("UPDATE users SET password = $1, salt = $2 WHERE id = $3 RETURNING id")
                .bind(hashed_password.hash)
                .bind(hashed_password.salt)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
        let updated_user = updated_user.ok_or(DBError::LogicError("Invalid user ID".into()))?;
        let updated_user =
            UserId::from_row(&updated_user).map_err(|e| DBError::OtherError(e.into()))?;
        if updated_user.id == user_id {
            tx.commit()
                .await
                .map_err(|e| DBError::QueryError(e.into()))?;
            Ok(())
        } else {
            Err(DBError::OtherError("IDs are not equal".into()))
        }
    }
}
