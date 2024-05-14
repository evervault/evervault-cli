use proc_macro2::{TokenStream as TokenStream2, TokenTree};

use crate::error::ParseMessageError;

// The parser intermediate representation of the Message struct
#[derive(Debug)]
pub struct ImMessage {
    pub content: Option<String>,
    pub code: Option<String>,
    pub exit_code: Option<i32>,
}

// Holds the desired outputs of the CliMessage trait whilst generating
// the tokens necessary for the impl
pub struct Message {
    pub content: String,
    pub code: String,
    pub exit_code: i32,
}

fn build_message_code_from_enum(enum_name: String, variant_name: String) -> String {
    format!(
        "{}-{}",
        to_kebab_case(enum_name),
        to_kebab_case(variant_name)
    )
}

fn to_kebab_case(s: String) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i > 0 && c.is_uppercase() {
                format!("-{}", c.to_lowercase())
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect::<String>()
}

enum SubAttr {
    Message,
    Code,
    ExitCode,
}

impl TryFrom<proc_macro2::Ident> for SubAttr {
    type Error = ParseMessageError;

    fn try_from(ident: proc_macro2::Ident) -> Result<Self, Self::Error> {
        match ident.to_string().as_str() {
            "message" => Ok(SubAttr::Message),
            "code" => Ok(SubAttr::Code),
            "exit_code" => Ok(SubAttr::ExitCode),
            _ => Err(ParseMessageError::UnknownIdent),
        }
    }
}

// Parses the token stream contained in wrapping parentheses of the message attr
// ie #[message(<token-stream>)]
pub fn parse_message_attribute(toks: TokenStream2) -> Result<ImMessage, ParseMessageError> {
    println!("{:?}", toks.to_string());
    let mut im = ImMessage {
        content: None,
        code: None,
        exit_code: None,
    };
    let mut ident_being_parsed: Option<SubAttr> = None;

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
                    ident_being_parsed = None;
                    continue;
                }

                if let Some(ident) = ident_being_parsed {
                    match ident {
                        SubAttr::Message => set_opt_once(&mut im.content, lit)?,
                        SubAttr::Code => set_opt_once(&mut im.code, lit)?,
                        SubAttr::ExitCode => {
                            let exit_code: i32 = lit
                                .parse()
                                .map_err(|e| ParseMessageError::ExitCodeParse(e))?;
                            set_opt_once(&mut im.exit_code, exit_code)?;
                        }
                    }
                } else {
                    return Err(ParseMessageError::LiteralWithoutIdent);
                }

                ident_being_parsed = None;
            }
            TokenTree::Ident(ident) => {
                ident_being_parsed = Some(SubAttr::try_from(ident)?);
            }
            _ => continue,
        }
    }

    Ok(im)
}

pub fn derive_message_from_im(
    im: ImMessage,
    enum_name: String,
    variant_name: String,
) -> Result<Message, ParseMessageError> {
    let content = match im.content {
        Some(content) => content,
        None => return Err(ParseMessageError::MissingMessageAttribute),
    };

    Ok(Message {
        content,
        code: im.code.unwrap_or_else(|| {
            build_message_code_from_enum(enum_name.to_string(), variant_name.to_string())
        }),
        exit_code: im.exit_code.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn it_can_extract_the_message_as_default_argument() {
        let toks = TokenStream2::from_str("\"Hello World\"").unwrap();
        let parsed = parse_message_attribute(toks).unwrap();
        assert_eq!(parsed.content.unwrap(), "Hello World");
    }

    #[test]
    fn it_can_extract_specified_message() {
        let toks = TokenStream2::from_str("message=\"Hello World\"").unwrap();
        let parsed = parse_message_attribute(toks).unwrap();
        assert_eq!(parsed.content.unwrap(), "Hello World");
    }

    #[test]
    fn it_can_extract_exit_code() {
        let toks = TokenStream2::from_str("exit_code=\"0\"").unwrap();
        let parsed = parse_message_attribute(toks);
        assert_eq!(parsed.unwrap().exit_code.unwrap(), 0);

        let toks = TokenStream2::from_str("message = \"test\", exit_code = \"5\"");
        println!("{:?}", toks);
        let parsed = parse_message_attribute(toks.unwrap()).unwrap();
        assert_eq!(parsed.exit_code.unwrap(), 5);
        assert_eq!(parsed.content.unwrap(), "test".to_string());
    }

    #[test]
    fn it_can_extract_code() {
        let toks = TokenStream2::from_str("code=\"test\"").unwrap();
        let parsed = parse_message_attribute(toks).unwrap();
        assert_eq!(parsed.code.unwrap(), "test");
    }

    #[test]
    fn it_errors_on_multiple_message_fields_with_default() {
        let toks = TokenStream2::from_str("\"Hello World\", message=\"Hello World\"");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());
    }

    #[test]
    fn it_errors_on_multiple_fields() {
        let toks = TokenStream2::from_str("message=\"Hello World\", message=\"Hello World\"");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());

        let toks = TokenStream2::from_str("code=\"Hello World\", code=\"test\"");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());

        let toks = TokenStream2::from_str("exit_code=\"0\", exit_code=\"5\"");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());
    }

    #[test]
    fn it_errors_on_unknown_ident() {
        let toks = TokenStream2::from_str("unknown=\"Hello World\"");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());
    }

    #[test]
    fn it_converts_to_kebab_case() {
        assert_eq!(
            build_message_code_from_enum("RelayCreate".into(), "Success".into()),
            "relay-create-success"
        );

        assert_eq!(to_kebab_case("RelayCreate".into()), "relay-create");
        assert_eq!(
            to_kebab_case("RelayCreateSuccess".into()),
            "relay-create-success"
        );
    }

    #[test]
    fn it_errors_on_raw_literals() {
        let toks = TokenStream2::from_str("=Hello World");
        let parsed = parse_message_attribute(toks.unwrap());
        assert!(parsed.is_err());
    }
}
