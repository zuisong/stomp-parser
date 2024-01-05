use stomp_parser_derive::HelloMacro;
use stomp_parser_derive::MyDefault;

pub trait HelloMacro {
    fn hello_macro();
}

#[derive(HelloMacro)]
struct Sunfei;

#[derive(HelloMacro)]
struct Sunface;

fn main() {
    println!("{:?}", User::default());
}

pub trait MyDefault {
    fn my_default();
}

#[derive(MyDefault, Debug)]
struct SomeData(u32, String);

#[derive(MyDefault, Debug)]
struct User {
    name: String,
    data: SomeData,
}
