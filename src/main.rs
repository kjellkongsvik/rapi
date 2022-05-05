use rocket::{get, routes};

mod openid;

#[macro_use]
extern crate rocket;

#[get("/")]
fn index(_c: openid::Claims) {}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}
