/*
 * Copyright (C) 2021  Aravinth Manivannan <realaravinth@batsense.net>
 *
 * Use of this source code is governed by the Apache 2.0 and/or the MIT
 * License.
 */
//!<div align="center"><h1>Actix Authentication Middleware</h1>
//!
//![![Documentation](https://img.shields.io/badge/docs-master-blue)](https://realaravinth.github.io/actix-auth-middleware/actix_auth_middleware/)
//![![Build](https://github.com/realaravinth/actix-auth-middleware/actions/workflows/linux.yml/badge.svg)](https://github.com/realaravinth/actix-auth-middleware/actions/workflows/linux.yml)
//![![codecov](https://codecov.io/gh/realaravinth/actix-auth-middleware/branch/master/graph/badge.svg?token=TYZXLOOHYQ)](https://codecov.io/gh/realaravinth/actix-auth-middleware)
//!
//![![dependency status](https://deps.rs/repo/github/realaravinth/actix-auth-middleware/status.svg)](https://deps.rs/repo/github/realaravinth/actix-auth-middleware)
//!
//!  <p>
//!    <strong>Checks if session is authenticated</strong>
//!  </p>
//!<br /></div>
//!
//! ## What
//!
//! This library provides a generic middleware to protect authenticated
//! routes from unauthenticated access. The middleware provides options to
//! customise authentication checking mechanism, which enables it to
//! support a wide range of session management mechanisms.
//!
//! If a session is authenticated, then the request will be dispatched to
//! the matching handler and if unauthenticated, it will be redirected to a
//! user specified route, ideally a sign in route.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use actix_auth_middleware::{Authentication, GetLoginRoute};
//!
//! use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
//! use actix_web::http::header;
//! use actix_web::FromRequest;
//! use actix_web::{App, HttpResponse, HttpServer};
//! use actix_web::{web, Responder};
//! use serde::Deserialize;
//!
//! pub struct Routes {
//!     signin: &'static str,
//!     authenticated_route: &'static str,
//! }
//!
//! impl Routes {
//!     const fn new() -> Self {
//!         let signin = "/siginin";
//!         let authenticated_route = "/";
//!
//!         Self {
//!             signin,
//!             authenticated_route,
//!         }
//!     }
//! }
//!
//! impl GetLoginRoute for Routes {
//!     fn get_login_route(&self, src: Option<&str>) -> String {
//!         if let Some(redirect_to) = src {
//!             format!(
//!                 "{}?redirect_to={}",
//!                 self.signin,
//!                 urlencoding::encode(redirect_to)
//!             )
//!         } else {
//!             self.signin.to_string()
//!         }
//!     }
//! }
//!
//! pub const ROUTES: Routes = Routes::new();
//!
//! fn get_middleware() -> Authentication<Routes> {
//!     Authentication::with_identity(ROUTES)
//! }
//!
//! fn get_identity_service() -> IdentityService<CookieIdentityPolicy> {
//!     IdentityService::new(
//!         CookieIdentityPolicy::new(&[0; 32])
//!             .path("/")
//!             .name("auth")
//!             .max_age_secs(60 * 60 * 24 * 365)
//!             .domain("localhost")
//!             .secure(false),
//!     )
//! }
//!
//! #[derive(Deserialize)]
//! pub struct RedirectQuery {
//!     pub redirect_to: Option<String>,
//! }
//!
//! #[my_codegen::get(path = "ROUTES.signin")]
//! async fn signin_route_hander(id: Identity, path: web::Query<RedirectQuery>) -> HttpResponse {
//!     id.remember("foo".into());
//!     println!("authenticated");
//!     let path = path.into_inner();
//!     if let Some(redirect_to) = path.redirect_to {
//!         println!("redirecting");
//!         HttpResponse::Found()
//!             .insert_header((header::LOCATION, redirect_to))
//!             .finish()
//!     } else {
//!         let page = format!(
//!             "
//!         <html>
//!         <body>
//!         <p>
//!         You are authenticated
//!         <a href='/{}'>Click here to view restricted resource</a>
//!         </p>
//!         </body>
//!         </html>
//!         ",
//!             ROUTES.authenticated_route
//!         );
//!         HttpResponse::Ok()
//!             .content_type("text/html; charset=utf-8")
//!             .body(page)
//!     }
//! }
//!
//! fn services(cfg: &mut web::ServiceConfig) {
//!     cfg.service(signin_route_hander);
//!     cfg.service(authenticated_route_handler);
//! }
//!
//! #[my_codegen::get(path = "ROUTES.authenticated_route", wrap = "get_middleware()")]
//! async fn authenticated_route_handler() -> impl Responder {
//!     HttpResponse::Ok()
//!         .content_type("text/html; charset=utf-8")
//!         .body("You are viewing a restricted resoucre")
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     HttpServer::new(move || App::new().wrap(get_identity_service()).configure(services))
//!         .bind("localhost:7000")
//!         .unwrap()
//!         .run()
//!         .await?;
//!     Ok(())
//! }
//!```
use std::rc::Rc;

use actix_http::body::AnyBody;
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{dev::Payload, http, Error, HttpRequest, HttpResponse};

use futures::future::{ok, Either, Ready};

/// The route to which unauthenticated sessions should be redirected to. `src` specifies the
/// destination of the request, which can be used to redirect the user post authentication
pub trait GetLoginRoute {
    ///
    /// ```rust
    ///use actix_auth_middleware::{Authentication, GetLoginRoute};
    ///
    /// pub struct Routes {
    ///     signin: &'static str,
    ///     authenticated_route: &'static str,
    /// }
    ///
    /// impl GetLoginRoute for Routes {
    /// // return login route and if redirection mechanism is implemented at the login
    /// // handler, then set redirection location
    ///     fn get_login_route(&self, src: Option<&str>) -> String {
    ///         if let Some(redirect_to) = src {
    ///             format!(
    ///                 "{}?redirect_to={}",
    ///                 self.signin,
    ///                 urlencoding::encode(redirect_to)
    ///             )
    ///         } else {
    ///             self.signin.to_string()
    ///         }
    ///     }
    /// }
    /// ```
    fn get_login_route(&self, src: Option<&str>) -> String;
}

/// Function to check if a request is authenticated
/// ```rust
/// # use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
/// # use actix_web::http::header;
/// # use actix_web::FromRequest;
/// # use actix_web::{dev::Payload, App, HttpRequest, HttpResponse, HttpServer};
/// # use actix_web::{web, Responder};
/// // implementation for actix::Identity based session managment
/// fn is_authenticated(r: &HttpRequest, pl: &mut Payload) -> bool {
///     matches!(
///         Identity::from_request(r, pl)
///             .into_inner()
///             .map(|id| id.identity()),
///         Ok(Some(_))
///     )
/// }
/// ```
pub type IsAuthenticated = fn(&HttpRequest, &mut Payload) -> bool;

/// Authentication middleware configuration
pub struct Authentication<T: GetLoginRoute> {
    login: Rc<T>,
    is_authenticated: IsAuthenticated,
}

impl<T: GetLoginRoute> Authentication<T> {
    /// Create a new instance of authentication middleware
    pub fn new(login: T, is_authenticated: IsAuthenticated) -> Self {
        let login = Rc::new(login);
        Self {
            login,
            is_authenticated,
        }
    }

    #[cfg(feature = "actix_identity_backend")]
    /// `actix::identity` backend
    pub fn with_identity(login: T) -> Authentication<T> {
        use actix_web::FromRequest;

        fn is_authenticated(r: &HttpRequest, pl: &mut Payload) -> bool {
            matches!(
                actix_identity::Identity::from_request(r, pl)
                    .into_inner()
                    .map(|id| id.identity()),
                Ok(Some(_))
            )
        }

        Authentication::new(login, is_authenticated)
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

/// Authentication middleware
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
    #[allow(clippy::type_complexity)]
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
    use actix_web::{dev::ServiceResponse, http::StatusCode};
    use actix_web::{test, web, Responder};
    use serde::Deserialize;
    use url::Url;

    fn get_middleware() -> Authentication<Routes> {
        Authentication::with_identity(ROUTES)
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
    async fn signin_route_hander(id: Identity, path: web::Query<RedirectQuery>) -> HttpResponse {
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
