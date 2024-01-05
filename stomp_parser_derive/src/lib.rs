use proc_macro::TokenStream;
use quote::quote;
use syn;
use syn::{Data, DeriveInput};

#[proc_macro_derive(HelloMacro)]
pub fn hello_macro_derive(input: TokenStream) -> TokenStream {
    // 基于 input 构建 AST 语法树
    let ast: DeriveInput = syn::parse(input).unwrap();

    // 构建特征实现代码
    impl_hello_macro(&ast)
}

fn impl_hello_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl HelloMacro for #name {
            fn hello_macro() {
                println!("Hello, Macro! My name is {}!", stringify!(#name));
            }
        }
    };
    gen.into()
}

#[proc_macro_derive(MyDefault)]
pub fn my_default(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let id = ast.ident;

    let Data::Struct(s) = ast.data else {
        panic!("MyDefault derive macro must use in struct");
    };
    // 声明一个新的ast，用于动态构建字段赋值的token
    let mut field_ast = quote! {};

    // 这里就是要动态添加token的地方了，需要动态完成Self的字段赋值
    for (idx, f) in s.fields.iter().enumerate() {
        let (field_id, field_ty) = (&f.ident, &f.ty);

        if let Some(field_id) = field_id {
            // 对于命名字段，都需要添加 `#field_name: #field_type::default(),` 这样的代码
            field_ast.extend(quote! { #field_id: <#field_ty>::default(), });
        } else {
            let field_idx = syn::Index::from(idx);
            let fty = &f.ty;
            //对于匿名字段，都需要添加 `#field_idx: <#field_type as std::default::Default>::default(),` 这样的代码
            field_ast.extend(quote! { #field_idx: <#fty>::default(), });
        }
    }

    let result = quote! {
        impl std::default::Default for #id {
            fn default() -> Self {
                Self { #field_ast }
            }
        }
    };

    result.into()
}
