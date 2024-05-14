extern crate proc_macro;

use std::collections::HashMap;

use proc_macro::TokenStream;

use proc_macro2::{TokenStream as TokenStream2, TokenTree};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Ident, Meta};

#[derive(Debug)]
struct ImMessage {
    content: Option<String>,
    code: Option<String>,
    exit_code: Option<i32>,
}

struct Message {
    content: String,
    code: String,
    exit_code: i32,
}

#[derive(Debug)]
enum ParseMessageError {
    MessageNotSet,
    FieldSetTwice,
    FailedToParseExitCode(std::num::ParseIntError),
    UnknownIdent,
}

fn parse_message_attribute(toks: TokenStream2) -> Result<ImMessage, ParseMessageError> {
    let mut im = ImMessage {
        content: None,
        code: None,
        exit_code: None,
    };
    let mut last_ident: Option<String> = None;

    fn set_opt_once<T>(opt: &mut Option<T>, val: T) -> Result<(), ParseMessageError> {
        if opt.is_some() {
            return Err(ParseMessageError::FieldSetTwice);
        }

        *opt = Some(val);
        Ok(())
    }

    for (i, tok) in toks.into_iter().enumerate() {
        match tok {
            TokenTree::Literal(lit) => {
                let lit = lit.to_string().replace("\"", "");

                // handle the default case where content is first arg
                if i == 0 {
                    im.content = Some(lit);
                    last_ident = None;
                    continue;
                }

                if let Some(ident) = last_ident {
                    match ident.as_str() {
                        "message" => set_opt_once(&mut im.content, lit)?,
                        "code" => set_opt_once(&mut im.code, lit)?,
                        "exit_code" => {
                            let exit_code: i32 = lit
                                .parse()
                                .map_err(|e| ParseMessageError::FailedToParseExitCode(e))?;
                            set_opt_once(&mut im.exit_code, exit_code)?
                        }
                        &_ => return Err(ParseMessageError::UnknownIdent),
                    }
                }

                last_ident = None;
            }
            TokenTree::Ident(ident) => {
                last_ident = Some(ident.to_string());

                match ident.to_string().as_str() {
                    "message" | "code" | "exit_code" => last_ident = Some(ident.to_string()),
                    &_ => {}
                }
            }
            _ => continue,
        }
    }

    Ok(im)
}

fn build_message_code_from_enum(enum_name: String, variant_name: String) -> String {
    format!(
        "{}-{}",
        to_kebab_case(enum_name),
        to_kebab_case(variant_name)
    )
}

fn to_kebab_case(s: String) -> String {
    let mut kebab = String::new();
    for (i, c) in s.chars().enumerate() {
        if i != 0 && c.is_uppercase() {
            kebab.push('-');
        }
        // should only be one chat unless weird chars are used in enums (which is usually a compile
        // error)
        c.to_lowercase()
            .for_each(|lowercased| kebab.push(lowercased));
    }
    kebab
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn it_can_extract_the_message_as_default_argument() {
        let toks = TokenStream2::from_str("\"Hello World\"").unwrap();
        let parsed = parse_message_attribute(toks).unwrap();
        assert_eq!(parsed.message.unwrap(), "Hello World");
    }

    #[test]
    fn it_can_extract_specified_message() {
        let toks = TokenStream2::from_str("message=\"Hello World\"").unwrap();
        let parsed = parse_message_attribute(toks).unwrap();
        assert_eq!(parsed.message.unwrap(), "Hello World");
    }

    #[test]
    fn it_can_extract_exit_code() {
        let toks = TokenStream2::from_str("exit_code=\"0\"").unwrap();
        let parsed = parse_message_attribute(toks);
        assert_eq!(parsed.unwrap().exit_code.unwrap(), 0);

        // let toks = TokenStream2::from_str("message = \"test\"\\, exit_code=\"5\"");
        // println!("{:?}", toks);
        // let parsed = parse_message_attribute(toks.unwrap()).unwrap();
        // assert_eq!(parsed.exit_code.unwrap(), 5);
        // assert_eq!(parsed.message.unwrap(), "\"test\"".to_string());
    }
}

fn compile_error_from_parse_error(variant_name: String, err: &ParseMessageError) -> TokenStream2 {
    let msg = match err {
        ParseMessageError::MessageNotSet => {
            format!("Message not set for variant: {}", variant_name)
        }
        ParseMessageError::FieldSetTwice => {
            format!("Message set twice for variant: {}", variant_name)
        }
        ParseMessageError::FailedToParseExitCode(parse_err) => {
            format!("Failed to parse exit code for variant: {}", parse_err)
        }
        ParseMessageError::UnknownIdent => {
            format!("Unknown ident for variant: {}", variant_name)
        }
    };

    quote! {
        compile_error!(#msg);
    }
}

/// Performs automatic implementation of the CliMessage trait for an enum
///
/// # Example
///
/// #[derive(CliMessage)]
/// pub enum RelayCreate {
///    #[message("Relay created successfully")]
///    Success,
///    #[message("A relay with this domain already exists")]
///    AlreadyExists,
///
/// }
#[proc_macro_derive(CliMessage, attributes(message))]
pub fn cli_message_derive(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let name = &input.ident;

    let data = match input.data {
        Data::Enum(data_enum) => data_enum,
        _ => {
            return quote! {
                compile_error!("CliMessage can only be derived for enums");
            }
            .into()
        }
    };

    let variants: Vec<Result<(&Ident, Message), ParseMessageError>> = data
        .variants
        .iter()
        .filter_map(|variant| {
            let variant_name = &variant.ident;
            let message_attr = variant.attrs.iter().find_map(|attr| {
                if let Meta::List(parts) = &attr.meta {
                    if parts.path.is_ident("message") {
                        return Some(parts);
                    }
                }
                None
            })?;

            println!("{:#?}", variant);
            let im = match parse_message_attribute(message_attr.tokens.clone()) {
                Ok(im) => im,
                Err(e) => return Some(Err(e)),
            };

            // message content is the only field we can't infer
            let content = match im.content {
                Some(content) => content,
                None => return Some(Err(ParseMessageError::MessageNotSet)),
            };

            let message = Message {
                content,
                code: im.code.unwrap_or_else(|| {
                    // build_message_code_from_enum(name.to_string(), variant_name.to_string())
                    "test".to_string()
                }),
                exit_code: im.exit_code.unwrap_or(0),
            };

            Some(Ok((variant_name, message)))
        })
        .collect();

    let mut tokens = HashMap::from([("content", vec![]), ("code", vec![]), ("exit_code", vec![])]);

    for variant in variants {
        match variant {
            Ok((variant_name, message)) => {
                let content = message.content;
                let code = message.code;
                let exit_code = message.exit_code;

                tokens.entry("content").and_modify(|v| {
                    v.push(quote! {
                        #name::#variant_name => #content.to_string()
                    })
                });

                tokens.entry("code").and_modify(|v| {
                    v.push(quote! {
                        #name::#variant_name => #code.to_string()
                    })
                });

                tokens.entry("exit_code").and_modify(|v| {
                    v.push(quote! {
                        #name::#variant_name => #exit_code
                    })
                });
            }
            Err(e) => return compile_error_from_parse_error(name.to_string(), &e).into(),
        }
    }

    let messages = tokens.get("content").expect("infallible");
    let codes = tokens.get("code").expect("infallible");
    let exit_codes = tokens.get("exit_code").expect("infallible");

    quote! {
        impl CliMessage for #name {
            fn message(&self) -> String {
                match self {
                    #(#messages),*
                }
            }

            fn code(&self) -> String {
                match self {
                    #(#codes),*
                }
            }

            fn exit_code(&self) -> i32 {
                match self {
                    #(#exit_codes),*
                }
            }
        }
    }
    .into()
}
