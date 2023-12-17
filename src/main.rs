use actix_web::{
    post,
    web::{self, Json},
    App, HttpResponse, HttpServer, Responder,
};
use auth::{
    database::{DBCLientPostgres, DBClient, DBError},
    middlewares::AppKeyMiddleware,
    models::{AuthenticationInfo, UserInfoIn},
    token::{TokenManager, TokenPair},
};
use std::sync::Mutex;

#[post("/register")]
async fn simple_registration(
    new_user_info: Json<UserInfoIn>,
    database: web::Data<Mutex<DBCLientPostgres>>,
) -> impl Responder {
    let database = database.lock().unwrap();
    let new_user_info = new_user_info.into_inner();
    let user_registration_result = database.add_user(new_user_info).await;
    let new_user_id = if let Err(e) = user_registration_result {
        match e {
            DBError::LogicError(e) => return HttpResponse::Conflict().body(e.to_string()),
            DBError::QueryError(e) => return HttpResponse::InternalServerError().body(e.to_string()),
            DBError::OtherError(e) => return HttpResponse::InternalServerError().body(e.to_string())
        }
    } else {
        user_registration_result.unwrap()
    };
    HttpResponse::Ok().body(serde_json::to_string(&new_user_id).unwrap())
}

#[post("/login")]
async fn simple_login(
    auth_data: Json<AuthenticationInfo>,
    database: web::Data<Mutex<DBCLientPostgres>>,
    token_manager: web::Data<Mutex<TokenManager>>,
) -> impl Responder {
    let database = database.lock().unwrap();
    let auth_data = auth_data.into_inner();
    let registration_flag = database.check_user_registration(auth_data).await;
    let is_user_registered = if let Err(e) = registration_flag {
        match e {
            DBError::LogicError(e) => return HttpResponse::Unauthorized().body(e.to_string()),
            DBError::QueryError(e) => return HttpResponse::InternalServerError().body(e.to_string()),
            DBError::OtherError(e) => return HttpResponse::InternalServerError().body(e.to_string())
        }
    } else {
        registration_flag.unwrap()
    };
    if let Some(user_id) = is_user_registered {
        let mut token_manager = token_manager.lock().unwrap();
        match token_manager
            .issue_new_tokens(user_id.to_string(), None)
            .await
        {
            Ok(new_tokens) => {
                return HttpResponse::Ok().body(serde_json::to_string(&new_tokens).unwrap())
            }
            Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        }
    } else {
        return HttpResponse::Unauthorized().body("User credentials are not correct");
    }
}

#[post("/refresh")]
async fn refresh_tokens(
    request: Json<TokenPair>,
    token_manager: web::Data<Mutex<TokenManager>>,
) -> impl Responder {
    let mut token_manager = token_manager.lock().unwrap();
    match token_manager
        .refresh_tokens(&request.access, &request.refresh)
        .await
    {
        Ok(Ok(new_pair)) => HttpResponse::Ok().body(serde_json::to_string(&new_pair).unwrap()),
        Ok(Err(conflict_time)) => HttpResponse::Conflict().body(conflict_time.to_string()),
        Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let token_manager = TokenManager::new().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            format!("Token manager error: {e}"),
        )
    })?;
    let token_manager = web::Data::new(Mutex::new(token_manager));
    let database = DBCLientPostgres::new().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            format!("Database connection error: {e}"),
        )
    })?;
    let database = web::Data::new(Mutex::new(database));
    HttpServer::new(move || {
        App::new()
            .app_data(database.clone())
            .app_data(token_manager.clone())
            .service(simple_login)
            .service(simple_registration)
            .service(refresh_tokens)
            .wrap(AppKeyMiddleware)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
