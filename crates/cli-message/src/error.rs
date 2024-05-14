use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

#[derive(Debug)]
pub enum ParseMessageError {
    MissingMessageAttribute,
    FieldSetTwice,
    ExitCodeParse(std::num::ParseIntError),
    UnknownIdent,
    LiteralWithoutIdent,
    UnsupportedDerived,
}

pub fn compile_error_from_parse_error(
    variant_name: String,
    err: &ParseMessageError,
) -> TokenStream2 {
    let msg = match err {
        ParseMessageError::MissingMessageAttribute => {
            format!(
                "{} contains variants which do not have a message attribute. \
            All variants in an enum deriving the CliMessage trait must have a message attribute.",
                variant_name
            )
        }
        ParseMessageError::FieldSetTwice => {
            format!(
                "Subattribute of Message attribute set twice for variant {}",
                variant_name
            )
        }
        ParseMessageError::ExitCodeParse(parse_err) => {
            format!(
                "Failed to parse provided exit code for variant to i32: {}",
                parse_err
            )
        }
        ParseMessageError::UnknownIdent => {
            format!("Unknown ident for variant: {}", variant_name)
        }
        ParseMessageError::LiteralWithoutIdent => {
            format!("Sub Attributes must be directly specified, positional arguments are not specified {}",
                variant_name)
        }
        ParseMessageError::UnsupportedDerived => {
            format!(
                "Attempted to derive CliMessage on an unsupported type only enums are supported"
            )
        }
    };

    quote! {
        compile_error!(#msg);
    }
}
