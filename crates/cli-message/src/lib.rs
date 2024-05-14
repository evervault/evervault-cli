extern crate proc_macro;

use proc_macro::TokenStream;

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Meta, Variant};

mod error;
mod parse;
mod tok;

use crate::parse::derive_message_from_im;
use error::ParseMessageError;
use parse::{parse_message_attribute, Message};
use tok::build_match_arm_toks;

fn impl_enum(
    data: syn::DataEnum,
    enum_name: &syn::Ident,
) -> Result<TokenStream2, ParseMessageError> {
    let mut variants_with_message: Vec<(&Variant, Message)> = Vec::new();

    for variant in data.variants.iter() {
        let message_attr = variant
            .attrs
            .iter()
            .find_map(|attr| {
                if let Meta::List(parts) = &attr.meta {
                    if parts.path.is_ident("message") {
                        return Some(parts);
                    }
                }
                None
            })
            .ok_or(())
            .map_err(|_| ParseMessageError::MissingMessageAttribute)?;

        let im = parse_message_attribute(message_attr.tokens.clone())?;
        let message = derive_message_from_im(im, enum_name.to_string(), variant.ident.to_string())?;

        variants_with_message.push((variant, message));
    }

    let (messages, codes, exit_codes) = build_match_arm_toks(variants_with_message, &enum_name);

    Ok(quote! {
        impl CliMessage for #enum_name {
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
    })
}

/// Performs automatic implementation of the CliMessage trait for an enum
#[proc_macro_derive(CliMessage, attributes(message, code, status_code))]
pub fn cli_message_derive(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let toks = match input.data {
        Data::Enum(data_enum) => impl_enum(data_enum, &input.ident),
        _ => Err(ParseMessageError::UnsupportedDerived),
    };

    match toks {
        Ok(toks) => TokenStream::from(toks),
        Err(err) => error::compile_error_from_parse_error(input.ident.to_string(), &err).into(),
    }
}
