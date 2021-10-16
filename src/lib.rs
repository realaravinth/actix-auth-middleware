/*
 * Copyright (C) 2021  Aravinth Manivannan <realaravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#![allow(clippy::type_complexity)]

use std::rc::Rc;

use actix_http::body::AnyBody;
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{dev::Payload, http, Error, HttpRequest, HttpResponse};

use futures::future::{ok, Either, Ready};

pub trait GetLoginRoute {
    fn get_login_route(&self, src: Option<&str>) -> String;
}

type IsAuthenticated = fn(&HttpRequest, &mut Payload) -> bool;

pub struct Authentication<T: GetLoginRoute> {
    login: Rc<T>,
    is_authenticated: IsAuthenticated,
}

impl<T: GetLoginRoute> Authentication<T> {
    pub fn new(login: T, is_authenticated: IsAuthenticated) -> Self {
        let login = Rc::new(login);
        Self {
            login,
            is_authenticated,
        }
    }
}

impl<S, GT> Transform<S, ServiceRequest> for Authentication<GT>
where
    S: Service<ServiceRequest, Response = ServiceResponse<AnyBody>, Error = Error>,
    S::Future: 'static,
    GT: GetLoginRoute,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, GT>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthenticationMiddleware {
            service,
            login: self.login.clone(),
            is_authenticated: self.is_authenticated,
            //          session_type: self.session_type.clone(),
        })
    }
}
pub struct AuthenticationMiddleware<S, GT: GetLoginRoute> {
    service: S,
    login: Rc<GT>,
    is_authenticated: IsAuthenticated,
}

impl<S, GT> Service<ServiceRequest> for AuthenticationMiddleware<S, GT>
where
    S: Service<ServiceRequest, Response = ServiceResponse<AnyBody>, Error = Error>,
    S::Future: 'static,
    GT: GetLoginRoute,
{
    type Response = ServiceResponse<AnyBody>;
    type Error = Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let (r, mut pl) = req.into_parts();

        if (self.is_authenticated)(&r, &mut pl) {
            let req = ServiceRequest::from_parts(r, pl);
            Either::Left(self.service.call(req))
        } else {
            let path = r.uri().path_and_query().map(|path| path.as_str());
            let path = self.login.get_login_route(path);
            let req = ServiceRequest::from_parts(r, pl);
            Either::Right(ok(req.into_response(
                HttpResponse::Found()
                    .insert_header((http::header::LOCATION, path))
                    .finish(),
            )))
        }
    }
}

#[cfg(test)]
#[macro_use]
mod tests {
    use super::*;

    use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
    use actix_web::cookie::Cookie;
    use actix_web::http::header;
    use actix_web::{dev::ServiceResponse, http::StatusCode, FromRequest};
    use actix_web::{test, web, Responder};
    use serde::Deserialize;
    use url::Url;

    fn is_authenticated(r: &HttpRequest, pl: &mut Payload) -> bool {
        matches!(
            Identity::from_request(r, pl)
                .into_inner()
                .map(|id| id.identity()),
            Ok(Some(_))
        )
    }

    fn get_middleware() -> Authentication<Routes> {
        Authentication::new(ROUTES, is_authenticated)
    }

    fn get_identity_service() -> IdentityService<CookieIdentityPolicy> {
        IdentityService::new(
            CookieIdentityPolicy::new(&[0; 32])
                .path("/")
                .name("auth")
                .max_age_secs(60 * 60 * 24 * 365)
                .domain("example.com")
                .secure(false),
        )
    }

    #[macro_export]
    macro_rules! get_cookie {
        ($resp:expr) => {
            $resp.response().cookies().next().unwrap().to_owned()
        };
    }

    #[macro_export]
    macro_rules! post_request {
        ($uri:expr) => {
            test::TestRequest::post().uri($uri)
        };

        ($uri:expr) => {
            test::TestRequest::post().uri($uri)
        };

        ($serializable:expr, $uri:expr, FORM) => {
            test::TestRequest::post().uri($uri).set_form($serializable)
        };
    }

    #[macro_export]
    macro_rules! get_app {
        ("APP") => {
            actix_web::App::new()
                .wrap(get_identity_service())
                .configure(services)
        };

        () => {
            test::init_service(get_app!("APP"))
        };
    }

    /// signin util
    pub async fn signin() -> ServiceResponse {
        let app = get_app!().await;

        let signin_resp = test::call_service(&app, post_request!(ROUTES.signin).to_request()).await;
        assert_eq!(signin_resp.status(), StatusCode::OK);
        signin_resp
    }

    pub async fn authenticated_route(cookies: Cookie<'_>) -> ServiceResponse {
        let app = get_app!().await;
        let auth_resp = test::call_service(
            &app,
            post_request!(ROUTES.authenticated_route)
                .cookie(cookies)
                .to_request(),
        )
        .await;
        assert_eq!(auth_resp.status(), StatusCode::OK);
        auth_resp
    }

    struct Routes {
        signin: &'static str,
        authenticated_route: &'static str,
    }

    impl Routes {
        const fn new() -> Self {
            let signin = "/siginin";
            let authenticated_route = "/authenticated/route";

            Self {
                signin,
                authenticated_route,
            }
        }
    }

    impl GetLoginRoute for Routes {
        fn get_login_route(&self, src: Option<&str>) -> String {
            if let Some(redirect_to) = src {
                format!(
                    "{}?redirect_to={}",
                    self.signin,
                    urlencoding::encode(redirect_to)
                )
            } else {
                self.signin.to_string()
            }
        }
    }

    const ROUTES: Routes = Routes::new();

    fn services(cfg: &mut web::ServiceConfig) {
        cfg.service(signin_route_hander);
        cfg.service(authenticated_route_handler);
    }

    #[derive(Deserialize)]
    pub struct RedirectQuery {
        pub redirect_to: Option<String>,
    }

    #[my_codegen::post(path = "ROUTES.signin")]
    async fn signin_route_hander(id: Identity, path: web::Path<RedirectQuery>) -> HttpResponse {
        id.remember("foo".into());
        let path = path.into_inner();
        if let Some(redirect_to) = path.redirect_to {
            HttpResponse::Found()
                .insert_header((header::LOCATION, redirect_to))
                .finish()
        } else {
            HttpResponse::Ok().into()
        }
    }

    #[my_codegen::post(path = "ROUTES.authenticated_route", wrap = "get_middleware()")]
    async fn authenticated_route_handler() -> impl Responder {
        HttpResponse::Ok()
    }

    #[actix_rt::test]
    async fn auth_middleware_works() {
        fn make_uri(path: &str, queries: &Option<Vec<(&str, &str)>>) -> String {
            let mut url = Url::parse("http://x/").unwrap();
            let final_path;
            url.set_path(path);

            if let Some(queries) = queries {
                {
                    let mut query_pairs = url.query_pairs_mut();
                    queries.iter().for_each(|(k, v)| {
                        query_pairs.append_pair(k, v);
                    });
                }

                final_path = format!("{}?{}", url.path(), url.query().unwrap());
            } else {
                final_path = url.path().to_string();
            }
            final_path
        }

        let queries = Some(vec![
            ("foo", "bar"),
            ("src", "/x/y/z"),
            ("with_q", "/a/b/c/?goo=x"),
        ]);

        let signin_resp = signin().await;
        let cookies = get_cookie!(signin_resp);

        let bench_routes = vec![
            (&ROUTES.authenticated_route, queries.clone()),
            (&ROUTES.authenticated_route, None),
        ];

        let app = get_app!().await;

        for (from, query) in bench_routes.iter() {
            let route = make_uri(from, query);
            let unauth_req = test::call_service(&app, post_request!(&route).to_request()).await;
            assert_eq!(unauth_req.status(), StatusCode::FOUND);

            let redirect_to = ROUTES.get_login_route(Some(&route));
            let headers = unauth_req.headers();
            assert_eq!(headers.get(header::LOCATION).unwrap(), &redirect_to);

            let auth_req = authenticated_route(cookies.clone()).await;
            assert_eq!(auth_req.status(), StatusCode::OK);
        }
    }
}
