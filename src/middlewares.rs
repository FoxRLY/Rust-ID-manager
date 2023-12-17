use actix_web::{
    self,
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
};

pub struct AppKeyMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AppKeyMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AppKeyMiddlewareInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AppKeyMiddlewareInner { service }))
    }
}

pub struct AppKeyMiddlewareInner<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AppKeyMiddlewareInner<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let app_key = std::env::var("APP_KEY").unwrap_or("password".into());
        let user_key = req.headers().get("Authorization").unwrap();
        let user_key = user_key.to_str().unwrap_or("".into());
        if &app_key != user_key {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Forbidden().finish().map_into_right_body();
            return Box::pin(async { Ok(ServiceResponse::new(req, res)) });
        }

        let res = self.service.call(req);
        Box::pin(async move {
            let res = res.await?;
            Ok(res.map_into_left_body())
        })
    }
}
