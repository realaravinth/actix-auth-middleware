/*
 * Copyright (C) 2022  Aravinth Manivannan <realaravinth@batsense.net>
 *
 * Use of this source code is governed by the Apache 2.0 and/or the MIT
 * License.
 */
use actix_auth_middleware::{Authentication, GetLoginRoute};

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::http::header;
use actix_web::{web, Responder};
use actix_web::{App, HttpResponse, HttpServer};
use serde::Deserialize;

pub struct Routes {
    signin: &'static str,
    authenticated_route: &'static str,
}

impl Routes {
    const fn new() -> Self {
        let signin = "/siginin";
        let authenticated_route = "/";

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

pub const ROUTES: Routes = Routes::new();

fn get_middleware() -> Authentication<Routes> {
    Authentication::with_identity(ROUTES)
}

fn get_identity_service() -> IdentityService<CookieIdentityPolicy> {
    IdentityService::new(
        CookieIdentityPolicy::new(&[0; 32])
            .path("/")
            .name("auth")
            .max_age_secs(60 * 60 * 24 * 365)
            .domain("localhost")
            .secure(false),
    )
}

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub redirect_to: Option<String>,
}

#[my_codegen::get(path = "ROUTES.signin")]
async fn signin_route_hander(id: Identity, path: web::Query<RedirectQuery>) -> HttpResponse {
    id.remember("foo".into());
    println!("authenticated");
    let path = path.into_inner();
    if let Some(redirect_to) = path.redirect_to {
        println!("redirecting");
        HttpResponse::Found()
            .insert_header((header::LOCATION, redirect_to))
            .finish()
    } else {
        let page = format!(
            "
        <html>
        <body>
        <p>
        You are authenticated
        <a href='/{}'>Click here to view restricted resource</a>
        </p>
        </body>
        </html>
        ",
            ROUTES.authenticated_route
        );
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(page)
    }
}

fn services(cfg: &mut web::ServiceConfig) {
    cfg.service(signin_route_hander);
    cfg.service(authenticated_route_handler);
}

#[my_codegen::get(path = "ROUTES.authenticated_route", wrap = "get_middleware()")]
async fn authenticated_route_handler() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("You are viewing a restricted resoucre")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(move || App::new().wrap(get_identity_service()).configure(services))
        .bind("localhost:7000")
        .unwrap()
        .run()
        .await?;
    Ok(())
}
