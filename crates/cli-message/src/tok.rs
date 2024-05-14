use std::collections::HashMap;

use quote::{format_ident, quote};
use syn::Fields;

use crate::parse::Message;

// contains the tokens for each match arm
type SubAttrToks = (
    Vec<proc_macro2::TokenStream>,
    Vec<proc_macro2::TokenStream>,
    Vec<proc_macro2::TokenStream>,
);

pub fn build_match_arm_toks(
    variants_with_message: Vec<(&syn::Variant, Message)>,
    enum_name: &syn::Ident,
) -> SubAttrToks {
    let mut arms = HashMap::from([("content", vec![]), ("code", vec![]), ("exit_code", vec![])]);

    for (variant, message) in variants_with_message {
        let variant_name = &variant.ident;

        let content = message.content;
        let code = message.code;
        let exit_code = message.exit_code;

        // creates a pattern for varients with fields like
        // Success(String, String) -> Success(_0, _1)
        let fields_pat = match &variant.fields {
            Fields::Unnamed(field) => {
                let vars = field
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format_ident!("_{}", i));
                Some(quote!((#(#vars),*)))
            }
            _ => None,
        };

        let lhs = match &fields_pat {
            Some(fields_pat) => quote! {
                #enum_name::#variant_name #fields_pat
            },
            None => quote! {
                #enum_name::#variant_name
            },
        };

        let content_rhs = match &fields_pat {
            Some(fields_pat) => quote! {
                format!(#content, #fields_pat)
            },
            None => quote! {
                #content.to_string()
            },
        };

        arms.entry("content").and_modify(|v| {
            v.push(quote! {
                #lhs => #content_rhs
            })
        });

        arms.entry("code").and_modify(|v| {
            v.push(quote! {
                #lhs => #code.to_string()
            })
        });

        arms.entry("exit_code").and_modify(|v| {
            v.push(quote! {
                #lhs => #exit_code
            })
        });
    }

    (
        arms.get("content").expect("infallible").to_vec(),
        arms.get("code").expect("infallible").to_vec(),
        arms.get("exit_code").expect("infallible").to_vec(),
    )
}
