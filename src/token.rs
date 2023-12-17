use std::error::Error;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use rand::RngCore;
use redis::{aio::Connection, AsyncCommands, Client};
use serde::{Deserialize, Serialize};

// Что мне надо сделать в этом модуле?
// настраиваемый генератор и валидатор токенов в одном лице. Да, в одном. данные для кодировки и
// раскодировки должны храниться в одном месте.
//
// Что он должен будет делать?
// 1) Проверять полученные токены на валидность
// 2) Генерировать новые токены
// 3) Рефрешить предыдущие токены
// 4) Держать в уме использованные рефреш-токены столько, сколько обозначена жизнь рефреш-токена

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    iss: String, // Специальное название сервиса
    sub: String, // Рефреш или аксес токен
    aud: String, // ID пользователя
    jti: String, // ID семейства токенов
    exp: u64,    // Когда станет невалидным
    iat: u64,    // Когда был выпущен
}

type TokenVerificationResult = Result<TokenPair, u64>;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access: String,
    pub refresh: String,
}

pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    validation_timeless: Validation,
    access_ttl: u64,
    refresh_ttl: u64,
    redis: Connection,
    pub is_asymmetric: bool,
    generator: OsRng,
    issuer: String,
    algorithm: Algorithm,
}

impl TokenManager {
    /// Конструктор менеджера токенов
    ///
    /// Конфигурируется только переменными окружения
    /// Перременные окружения:
    /// ACCESS_TTL - 1200
    /// REFRESH_TTL - 604800
    /// ALGORRITHM - HMAC256 (HMAC256, HMAC512, RSA256, RSA512)
    /// ISSUER - auth
    /// PRIVATE_KEY - password
    /// PUBLIC_KEY - обязательное поле, если используются RSA алгоритмы
    pub async fn new() -> Result<TokenManager, Box<dyn Error>> {
        let access_ttl = std::env::var("ACCESS_TTL")
            .unwrap_or("1200".into())
            .trim()
            .parse::<u64>()
            .map_err(|_| "Cannot set access ttl")?;
        let refresh_ttl = std::env::var("REFRESH_TTL")
            .unwrap_or("604800".into())
            .trim()
            .parse::<u64>()
            .map_err(|_| "Cannot set refresh ttl")?;
        let algorithm = std::env::var("ALGORITHM")
            .unwrap_or("hmac256".into())
            .trim()
            .to_lowercase();
        let algorithm = match algorithm.to_lowercase().as_str() {
            "hmac256" => Algorithm::HS256,
            "rsa256" => Algorithm::RS256,
            "hmac512" => Algorithm::HS512,
            "rsa512" => Algorithm::RS512,
            _ => {
                println!("Invalid algorithm, reverting to HMAC256");
                Algorithm::HS256
            }
        };
        let issuer = std::env::var("ISSUER")
            .unwrap_or("auth".into())
            .trim()
            .to_owned();
        let encoding_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
            println!("Private key is not set. Default !INSECURE! key is 'password'");
            "password".into()
        });
        let (encoding_key, decoding_key, is_asymmetric) =
            if let Algorithm::RS256 | Algorithm::RS512 = algorithm {
                let decoding_key = std::env::var("PUBLIC_KEY")
                    .map_err(|_| "Public key is not set although algorithm is asymmetric")?;
                let decoding_key = DecodingKey::from_rsa_pem(decoding_key.trim().as_bytes())
                    .map_err(|_| "Public key is not PEM encoded")?;
                let encoding_key = EncodingKey::from_rsa_pem(encoding_key.trim().as_bytes())
                    .map_err(|_| "Private key is not PEM encoded")?;
                (encoding_key, decoding_key, true)
            } else {
                let decoding_key = DecodingKey::from_secret(encoding_key.trim().as_bytes());
                let encoding_key = EncodingKey::from_secret(encoding_key.trim().as_bytes());
                (encoding_key, decoding_key, false)
            };

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&issuer]);
        validation.sub = Some("refresh".into());

        let mut validation_timeless = validation.clone();
        validation_timeless.validate_exp = false;
        validation_timeless.sub = Some("access".into());
        

        
        let addr = format!(
            "redis://{}:6379",
            std::env::var("REDIS_CONTAINER_NAME").unwrap_or("localhost".into())
        );
        let redis =
            Client::open(addr).map_err(|_| "Redis client cannot connect to db".to_owned())?;
        let redis = redis
            .get_tokio_connection()
            .await
            .map_err(|_| "Redis connection cannot be established".to_owned())?;

        Ok(TokenManager {
            encoding_key,
            decoding_key,
            is_asymmetric,
            access_ttl,
            refresh_ttl,
            validation_timeless,
            validation,
            redis,
            generator: OsRng,
            issuer,
            algorithm,
        })
    }

    pub async fn clear_blacklist_and_used_tokens(&mut self) -> Result<(), Box<dyn Error>> {
        redis::cmd("FLUSHALL")
            .arg("SYNC")
            .query_async(&mut self.redis)
            .await
            .map_err(|_| "Cannot clear memory")?;
        Ok(())
    }

    async fn set_token_family_blacklisted(&mut self, jti: &str) -> Result<(), Box<dyn Error>> {
        self.redis
            .set(jti, 0)
            .await
            .map_err(|_| "Cannot set value in Redis")?;
        self.redis
            .expire(jti, self.refresh_ttl as usize)
            .await
            .map_err(|_| "Cannot expire value in Redis")?;
        Ok(())
    }

    async fn check_token_family_blacklist(&mut self, jti: &str) -> Result<(), Box<dyn Error>> {
        let is_blacklisted: Option<i32> = self
            .redis
            .get(jti)
            .await
            .map_err(|_| "Cannot get value from Redis")?;
        if is_blacklisted.is_some() {
            Err("Token is blacklisted")?;
        }
        Ok(())
    }

    async fn check_refresh_token_usage(
        &mut self,
        refresh_token: &str,
    ) -> Result<bool, Box<dyn Error>> {
        // Проверка токена на использованность
        let is_token_used: Option<i32> = self
            .redis
            .get(refresh_token)
            .await
            .map_err(|_| "Cannot get value from Redis")?;
        if let Some(_) = is_token_used {
            return Ok(true);
        }

        // Если он не использован - заносим его в редиску
        self.redis
            .set(refresh_token, 0)
            .await
            .map_err(|_| "Cannnot save token in Redis")?;
        self.redis
            .expire(refresh_token, self.refresh_ttl as usize)
            .await
            .map_err(|_| "Cannot set expire in Redis")?;
        Ok(false)
    }

    /// Функция обновления токенов
    ///
    /// Проверяет полученные токены на валидность
    /// Полученные токены должны быть из одной пары
    ///
    /// Выдает новые токены, если эти прошли проверку
    ///
    /// Если токены не прошли проверку целостности, однопарности и блэклиста, то возвращает ошибку
    /// Если токен рефреша был использован, то возвращает результат с временем, когда произошло
    /// обнаружение данного инцидента
    /// Если токены прошли все проверки и не были повторно использованы, то возвращает новую пару
    pub async fn refresh_tokens(
        &mut self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<TokenVerificationResult, Box<dyn Error>> {
        // Проверяем токены на валидность в обычном плане
        let refresh = decode::<Claims>(refresh_token, &self.decoding_key, &self.validation)
            .map_err(|_| "Refresh token validation failed")?
            .claims;
        let access = decode::<Claims>(access_token, &self.decoding_key, &self.validation_timeless)
            .map_err(|_| "Accesss token validation failed")?
            .claims;

        // Проверяем, пришли ли токены из одной пары
        if (&refresh.aud, &refresh.jti) != (&access.aud, &access.jti) {
            Err("Refresh and access tokens are not from one source")?;
        }

        // Проверяем, находится ли семейство токенов в черном списке
        self.check_token_family_blacklist(&refresh.jti).await?;

        // Проверяем, был ли рефреш-токен использован повторно
        if self.check_refresh_token_usage(refresh_token).await? {
            // Если да, то помещаем семейство токенов в блэклист
            // и отправляем время обнаружения хищения токена,
            // чтобы можно было отозвать и токен доступа, сравнив время его выдачи
            // с временем обнаружения - если токен доступа был выпущен раньше этого времени, то
            // его следует инвалидировать
            self.set_token_family_blacklisted(&refresh.jti).await?;
            return Ok(Err(jsonwebtoken::get_current_timestamp() + 5));
        }

        // После всех проверок создаем новую пару того же семейства
        let new_pair = self
            .issue_new_tokens(refresh.aud, Some(refresh.jti))
            .await?;

        Ok(Ok(new_pair))
    }

    pub async fn issue_new_tokens(
        &mut self,
        user_id: String,
        jti: Option<String>,
    ) -> Result<TokenPair, Box<dyn Error>> {
        // Если есть id сессии, то используем его, иначе генерируем новый
        let jti = if let Some(value) = jti {
            value
        } else {
            format!(
                "{}.{}",
                jsonwebtoken::get_current_timestamp(),
                self.generator.next_u32()
            )
        };
        let iss = self.issuer.to_owned();
        let aud = user_id;
        let iat = jsonwebtoken::get_current_timestamp();
        let exp = iat + self.refresh_ttl;

        // Создаем структуру токенов
        let refresh_claims = Claims {
            iss,
            aud,
            sub: "refresh".into(),
            jti,
            iat,
            exp,
        };
        let mut access_claims = refresh_claims.clone();
        access_claims.sub = "access".into();
        access_claims.exp = access_claims.iat + self.access_ttl;

        // На основе структур генерируем новые токены
        let refresh_token = encode(
            &Header::new(self.algorithm),
            &refresh_claims,
            &self.encoding_key,
        )
        .map_err(|_| "Token cannot be generated")?;
        let access_token = encode(
            &Header::new(self.algorithm),
            &access_claims,
            &self.encoding_key,
        )
        .map_err(|_| "Token cannnot be generated")?;
        Ok(TokenPair {
            access: access_token,
            refresh: refresh_token,
        })
    }
}
