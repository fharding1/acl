#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use serde::{Serialize,Deserialize};
use rocket_contrib::json::Json;
use jsonwebtoken::{decode,encode,get_current_timestamp,Algorithm,DecodingKey,EncodingKey,Header,Validation};

#[derive(Serialize, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

const key: &[u8] = b"99023a4b-186c-41b8-9817-0a0d232f2402";

#[post("/login", format = "application/json", data = "<credentials>")]
fn login(credentials: Json<Credentials>) -> String {
    let claims = Claims {
        sub: credentials.username.to_owned(),
        exp: get_current_timestamp() + 60,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).expect("asdf")
}

#[derive(Serialize)]
enum Section {
    General,
    Sports,
    Tech,
}

#[derive(Serialize)]
struct Article {
    headline: String,
    content: String,
    section: Section,
}

#[get("/news")]
fn news() -> Json<Vec<Article>> {
    Json(Vec::from([Article{headline: "Lorem ipsum".to_string(), content: "bla bla bla bla bla".to_string(), section: Section::General}]))
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

fn main() {
    rocket::ignite().mount("/", routes![index, news, login]).launch();
}
