// TODO:
// - add type checks
// - add malleability checks
// - add stack limits and other safety checks

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use core::str::FromStr;

use hex::{self, FromHex};

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_while_m_n},
    character::complete::{alpha1, char, digit1},
    combinator::{all_consuming, cut, map, map_res, opt, verify},
    multi::{many0, many_m_n, separated_list1},
    sequence::{delimited, pair, preceded, terminated, tuple},
    Finish, IResult,
};

use bitcoin::consensus::encode::{self, VarInt};

use vanadium_sdk::crypto::CtxSha256;

use super::merkle::MerkleTree;

const HARDENED_INDEX: u32 = 0x80000000u32;

const MAX_OLDER_AFTER: u32 = 2147483647; // maximum allowed in older/after

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, PartialEq, Eq)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyInformation {
    pub pubkey: String,
    pub origin_info: Option<KeyOrigin>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct KeyPlaceholder {
    pub key_index: u32,
    pub num1: u32,
    pub num2: u32,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DescriptorTemplate {
    Sh(Box<DescriptorTemplate>),
    Wsh(Box<DescriptorTemplate>),
    Pkh(KeyPlaceholder),
    Wpkh(KeyPlaceholder),
    Sortedmulti(u32, Vec<KeyPlaceholder>),
    Sortedmulti_a(u32, Vec<KeyPlaceholder>),
    Tr(KeyPlaceholder, Option<TapTree>),

    Zero,
    One,
    Pk(KeyPlaceholder),
    Pk_k(KeyPlaceholder),
    Pk_h(KeyPlaceholder),
    Older(u32),
    After(u32),
    Sha256([u8; 32]),
    Ripemd160([u8; 20]),
    Hash256([u8; 32]),
    Hash160([u8; 20]),
    Andor(
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
    ),
    And_v(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_n(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_c(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_d(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_i(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Thresh(u32, Vec<DescriptorTemplate>),
    Multi(u32, Vec<KeyPlaceholder>),
    Multi_a(u32, Vec<KeyPlaceholder>),

    // wrappers
    A(Box<DescriptorTemplate>),
    S(Box<DescriptorTemplate>),
    C(Box<DescriptorTemplate>),
    T(Box<DescriptorTemplate>),
    D(Box<DescriptorTemplate>),
    V(Box<DescriptorTemplate>),
    J(Box<DescriptorTemplate>),
    N(Box<DescriptorTemplate>),
    L(Box<DescriptorTemplate>),
    U(Box<DescriptorTemplate>),
}

pub struct DescriptorTemplateIter<'a> {
    fragments: Vec<&'a DescriptorTemplate>,
    placeholders: Vec<&'a KeyPlaceholder>,
}

impl<'a> From<&'a DescriptorTemplate> for DescriptorTemplateIter<'a> {
    fn from(desc: &'a DescriptorTemplate) -> Self {
        let mut fragments = Vec::new();
        fragments.push(desc);
        DescriptorTemplateIter {
            fragments,
            placeholders: Vec::new(),
        }
    }
}

impl<'a> Iterator for DescriptorTemplateIter<'a> {
    type Item = &'a KeyPlaceholder;

    fn next(&mut self) -> Option<Self::Item> {
        // If there are pending placeholders, pop and return one
        if let Some(key) = self.placeholders.pop() {
            return Some(key);
        }

        while let Some(desc) = self.fragments.pop() {
            match desc {
                DescriptorTemplate::Sh(sub)
                | DescriptorTemplate::Wsh(sub)
                | DescriptorTemplate::A(sub)
                | DescriptorTemplate::S(sub)
                | DescriptorTemplate::C(sub)
                | DescriptorTemplate::T(sub)
                | DescriptorTemplate::D(sub)
                | DescriptorTemplate::V(sub)
                | DescriptorTemplate::J(sub)
                | DescriptorTemplate::N(sub)
                | DescriptorTemplate::L(sub)
                | DescriptorTemplate::U(sub) => {
                    self.fragments.push(sub);
                }

                DescriptorTemplate::Andor(sub1, sub2, sub3) => {
                    self.fragments.push(sub1);
                    self.fragments.push(sub2);
                    self.fragments.push(sub3);
                }

                DescriptorTemplate::Or_b(sub1, sub2)
                | DescriptorTemplate::Or_c(sub1, sub2)
                | DescriptorTemplate::Or_d(sub1, sub2)
                | DescriptorTemplate::Or_i(sub1, sub2)
                | DescriptorTemplate::And_v(sub1, sub2)
                | DescriptorTemplate::And_b(sub1, sub2)
                | DescriptorTemplate::And_n(sub1, sub2) => {
                    self.fragments.push(sub1);
                    self.fragments.push(sub2);
                }

                DescriptorTemplate::Tr(key, _)
                | DescriptorTemplate::Pkh(key)
                | DescriptorTemplate::Wpkh(key)
                | DescriptorTemplate::Pk(key)
                | DescriptorTemplate::Pk_k(key)
                | DescriptorTemplate::Pk_h(key) => {
                    return Some(key);
                }

                DescriptorTemplate::Sortedmulti(_, keys)
                | DescriptorTemplate::Sortedmulti_a(_, keys)
                | DescriptorTemplate::Multi(_, keys)
                | DescriptorTemplate::Multi_a(_, keys) => {
                    // Push keys onto the keys stack in reverse order
                    for key in keys.iter().rev() {
                        self.placeholders.push(key);
                    }
                }

                DescriptorTemplate::Thresh(_, descs) => {
                    for desc in descs.iter().rev() {
                        self.fragments.push(desc);
                    }
                }

                _ => {}
            }
        }

        None
    }
}

impl DescriptorTemplate {
    /// Determines if root fragment is a wrapper.
    fn is_wrapper(&self) -> bool {
        match &self {
            DescriptorTemplate::A(_) => true,
            DescriptorTemplate::S(_) => true,
            DescriptorTemplate::C(_) => true,
            DescriptorTemplate::T(_) => true,
            DescriptorTemplate::D(_) => true,
            DescriptorTemplate::V(_) => true,
            DescriptorTemplate::J(_) => true,
            DescriptorTemplate::N(_) => true,
            DescriptorTemplate::L(_) => true,
            DescriptorTemplate::U(_) => true,
            _ => false,
        }
    }
    pub fn placeholders(&self) -> DescriptorTemplateIter {
        DescriptorTemplateIter::from(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TapTree {
    Script(Box<DescriptorTemplate>),
    Branch(Box<TapTree>, Box<TapTree>),
}

impl KeyInformation {
    pub fn to_string(&self) -> String {
        match &self.origin_info {
            Some(origin_info) => {
                let path = origin_info
                    .derivation_path
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join("/");

                format!("[{}]{}/{}", origin_info.fingerprint, path, self.pubkey)
            }
            None => self.pubkey.clone(),
        }
    }
}

trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, &'static str>;
}

// Creates a parser that recognizes a number between 0 and `n` (both included).
// The returned parser will only accept the number if it doesn't have leading zeros,
// unless the number is exactly "0".
fn parse_number_up_to(n: u32) -> impl Fn(&str) -> IResult<&str, u32> {
    move |input: &str| {
        let mut parser = verify(map_res(digit1, str::parse::<u32>), |&num| {
            num <= n && ((num == 0 && !input.starts_with("00")) || !input.starts_with('0'))
        });
        parser(input)
    }
}

fn parse_descriptor_template(input: &str) -> Result<DescriptorTemplate, &'static str> {
    match parse_descriptor(input) {
        Ok((rest, descriptor)) => {
            if rest.is_empty() {
                Ok(descriptor)
            } else {
                Err("Failed to parse descriptor template: extra input remaining")
            }
        }
        Err(e) => Err("Failed to parse descriptor template"),
    }
}

fn parse_derivation_step_number(input: &str) -> IResult<&str, u32> {
    let (input, (num, hardened)) =
        pair(parse_number_up_to(HARDENED_INDEX - 1), opt(char('\'')))(input)?;

    let result = if hardened.is_some() {
        num + HARDENED_INDEX
    } else {
        num
    };
    Ok((input, result))
}

fn parse_key_origin(input: &str) -> IResult<&str, KeyOrigin> {
    let is_lowercase_hex_digit = |c: char| (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    let parse_fingerprint = map(take_while_m_n(8, 8, is_lowercase_hex_digit), |s: &str| {
        u32::from_str_radix(s, 16).unwrap()
    });
    let parse_derivation_path = many0(preceded(char('/'), parse_derivation_step_number));

    let (input, (fingerprint, derivation_path)) = delimited(
        char('['),
        cut(tuple((parse_fingerprint, parse_derivation_path))),
        char(']'),
    )(input)?;

    Ok((
        input,
        KeyOrigin {
            fingerprint,
            derivation_path,
        },
    ))
}

fn parse_key_information(input: &str) -> IResult<&str, KeyInformation> {
    all_consuming(map(
        pair(opt(parse_key_origin), parse_extended_public_key),
        |(origin_info, pubkey)| KeyInformation {
            pubkey,
            origin_info,
        },
    ))(input)
}

fn parse_extended_public_key(input: &str) -> IResult<&str, String> {
    map(
        take_while_m_n(111, 112, |c| BASE58_ALPHABET.contains(c)),
        |s: &str| String::from(s),
    )(input)
}

fn parse_key_placeholder(input: &str) -> IResult<&str, KeyPlaceholder> {
    let (input, key_index) = delimited(char('@'), parse_number_up_to(u32::MAX), char('/'))(input)?;

    // "**"
    let parse_double_star = map(tag::<&str, &str, nom::error::Error<&str>>("**"), |_| {
        (0u32, 1u32)
    });

    // "<NUM;NUM>/*"
    let parse_num_pair = map(
        delimited(
            char('<'),
            tuple((
                parse_derivation_step_number, // TODO: we only want to accept unhardened
                char(';'),
                parse_derivation_step_number,
            )),
            tag(">/*"),
        ),
        |(num1, _, num2)| (num1, num2),
    );

    let (input, (num1, num2)) = alt((parse_double_star, parse_num_pair))(input)?;

    Ok((
        input,
        KeyPlaceholder {
            key_index,
            num1,
            num2,
        },
    ))
}

fn parse_descriptor(input: &str) -> IResult<&str, DescriptorTemplate> {
    let (input, wrappers) = opt(terminated(alpha1, char(':')))(input)?;

    let wrappers = wrappers.unwrap_or("");

    let (input, inner_descriptor) = alt((
        parse_sh,
        parse_wsh,
        parse_pkh,
        parse_wpkh,
        parse_multi,
        parse_sortedmulti,
        parse_multi_a,
        parse_sortedmulti_a,
        parse_tr,
        parse_zero,
        parse_one,
        parse_pk,
        parse_pk_k,
        parse_pk_h,
        parse_older,
        parse_after,
        parse_sha256,
        parse_ripemd160,
        parse_hash256,
        parse_hash160,
        alt((
            parse_andor,
            parse_and_b,
            parse_and_v,
            parse_or_b,
            parse_or_c,
            parse_or_d,
            parse_or_i,
            parse_thresh,
        )),
    ))(input)?;

    let mut result = inner_descriptor;

    for wrapper in wrappers.chars().rev() {
        match wrapper {
            'a' => result = DescriptorTemplate::A(Box::new(result)),
            's' => result = DescriptorTemplate::S(Box::new(result)),
            'c' => result = DescriptorTemplate::C(Box::new(result)),
            't' => result = DescriptorTemplate::T(Box::new(result)),
            'd' => result = DescriptorTemplate::D(Box::new(result)),
            'v' => result = DescriptorTemplate::V(Box::new(result)),
            'j' => result = DescriptorTemplate::J(Box::new(result)),
            'n' => result = DescriptorTemplate::N(Box::new(result)),
            'l' => result = DescriptorTemplate::L(Box::new(result)),
            'u' => result = DescriptorTemplate::U(Box::new(result)),
            _ => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Alpha,
                )))
            }
        }
    }

    Ok((input, result))
}

fn parse_fragment_with_placeholder(
    tag_str: &'static str,
    template_constructor: impl Fn(KeyPlaceholder) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);

        let (input, key_placeholder) = delimited(
            tag(tag_with_parenthesis.as_str()),
            parse_key_placeholder,
            char(')'),
        )(input)?;

        Ok((input, template_constructor(key_placeholder)))
    }
}

fn parse_fragment_with_n_scripts(
    tag_str: &'static str,
    n: usize,
    template_constructor: impl Fn(&mut Vec<DescriptorTemplate>) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);

        let (input, mut scripts) = verify(
            delimited(
                tag(tag_with_parenthesis.as_str()),
                separated_list1(char(','), parse_descriptor),
                char(')'),
            ),
            |scripts: &Vec<DescriptorTemplate>| scripts.len() == n,
        )(input)?;

        Ok((input, template_constructor(&mut scripts)))
    }
}

fn parse_fragment_with_threshold_and_placeholders(
    tag_str: &'static str,
    template_constructor: fn(u32, Vec<KeyPlaceholder>) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);
        let parse_threshold = map_res(digit1, str::parse::<u32>);
        let parse_key_placeholders = many_m_n(2, 20, preceded(char(','), parse_key_placeholder));

        let (input, (threshold, key_placeholders)) = delimited(
            tag(tag_with_parenthesis.as_str()),
            pair(parse_threshold, parse_key_placeholders),
            char(')'),
        )(input)?;

        Ok((input, template_constructor(threshold, key_placeholders)))
    }
}

fn parse_fragment_with_number(
    tag_str: &'static str,
    max_n: u32,
    template_constructor: impl Fn(u32) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);

        let (input, number) = delimited(
            tag(tag_with_parenthesis.as_str()),
            parse_number_up_to(max_n),
            char(')'),
        )(input)?;

        Ok((input, template_constructor(number)))
    }
}

fn parse_fragment_with_hex20(
    tag_str: &'static str,
    template_constructor: impl Fn([u8; 20]) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);

        let (input, hex_string) = delimited(
            tag(tag_with_parenthesis.as_str()),
            take(2 * 20usize),
            char(')'),
        )(input)?;

        let decoded = <[u8; 20]>::from_hex(hex_string).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
        })?;

        Ok((input, template_constructor(decoded)))
    }
}

fn parse_fragment_with_hex32(
    tag_str: &'static str,
    template_constructor: impl Fn([u8; 32]) -> DescriptorTemplate,
) -> impl Fn(&str) -> IResult<&str, DescriptorTemplate> {
    move |input: &str| {
        let tag_with_parenthesis = format!("{}(", tag_str);

        let (input, hex_string) = delimited(
            tag(tag_with_parenthesis.as_str()),
            take(2 * 32usize),
            char(')'),
        )(input)?;

        let decoded = <[u8; 32]>::from_hex(hex_string).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::MapRes))
        })?;

        Ok((input, template_constructor(decoded)))
    }
}

fn parse_pk(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_placeholder("pk", DescriptorTemplate::Pk)(input)
}

fn parse_pkh(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_placeholder("pkh", DescriptorTemplate::Pkh)(input)
}

fn parse_wpkh(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_placeholder("wpkh", DescriptorTemplate::Wpkh)(input)
}

fn parse_sh(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("sh", 1, |scripts: &mut Vec<DescriptorTemplate>| {
        DescriptorTemplate::Sh(Box::new(scripts.remove(0)))
    })(input)
}

fn parse_wsh(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("wsh", 1, |scripts: &mut Vec<DescriptorTemplate>| {
        DescriptorTemplate::Wsh(Box::new(scripts.remove(0)))
    })(input)
}

fn parse_multi(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_threshold_and_placeholders("multi", DescriptorTemplate::Multi)(input)
}

fn parse_sortedmulti(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_threshold_and_placeholders("sortedmulti", DescriptorTemplate::Sortedmulti)(
        input,
    )
}

fn parse_multi_a(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_threshold_and_placeholders("multi_a", DescriptorTemplate::Multi_a)(input)
}

fn parse_sortedmulti_a(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_threshold_and_placeholders(
        "sortedmulti_a",
        DescriptorTemplate::Sortedmulti_a,
    )(input)
}

fn parse_zero(input: &str) -> IResult<&str, DescriptorTemplate> {
    map(tag("0"), |_| DescriptorTemplate::Zero)(input)
}

fn parse_one(input: &str) -> IResult<&str, DescriptorTemplate> {
    map(tag("1"), |_| DescriptorTemplate::One)(input)
}

fn parse_pk_k(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_placeholder("pk_k", DescriptorTemplate::Pk_k)(input)
}

fn parse_pk_h(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_placeholder("pk_h", DescriptorTemplate::Pk_h)(input)
}

fn parse_older(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_number("older", MAX_OLDER_AFTER, DescriptorTemplate::Older)(input)
}

fn parse_after(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_number("after", MAX_OLDER_AFTER, DescriptorTemplate::After)(input)
}

fn parse_sha256(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_hex32("sha256", DescriptorTemplate::Sha256)(input)
}

fn parse_ripemd160(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_hex20("ripemd160", DescriptorTemplate::Ripemd160)(input)
}

fn parse_hash256(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_hex32("hash256", DescriptorTemplate::Hash256)(input)
}

fn parse_hash160(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_hex20("hash160", DescriptorTemplate::Hash160)(input)
}

fn parse_andor(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("andor", 3, |scripts| {
        let x = Box::new(scripts.remove(0));
        let y = Box::new(scripts.remove(0));
        let z = Box::new(scripts.remove(0));
        DescriptorTemplate::Andor(x, y, z)
    })(input)
}

fn parse_and_b(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("and_b", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let y = Box::new(scripts.remove(0));
        DescriptorTemplate::And_b(x, y)
    })(input)
}

fn parse_and_v(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("and_v", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let y = Box::new(scripts.remove(0));
        DescriptorTemplate::And_v(x, y)
    })(input)
}

fn parse_or_b(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("or_b", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let z = Box::new(scripts.remove(0));
        DescriptorTemplate::Or_b(x, z)
    })(input)
}

fn parse_or_c(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("or_c", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let z = Box::new(scripts.remove(0));
        DescriptorTemplate::Or_c(x, z)
    })(input)
}

fn parse_or_d(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("or_d", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let z = Box::new(scripts.remove(0));
        DescriptorTemplate::Or_d(x, z)
    })(input)
}
fn parse_or_i(input: &str) -> IResult<&str, DescriptorTemplate> {
    parse_fragment_with_n_scripts("or_i", 2, |scripts| {
        let x = Box::new(scripts.remove(0));
        let z = Box::new(scripts.remove(0));
        DescriptorTemplate::Or_i(x, z)
    })(input)
}

fn parse_thresh(input: &str) -> IResult<&str, DescriptorTemplate> {
    let (input, k) = delimited(tag("thresh("), parse_number_up_to(u32::MAX), char(','))(input)?;

    let (input, scripts) = verify(
        terminated(separated_list1(char(','), parse_descriptor), char(')')),
        |scripts: &Vec<DescriptorTemplate>| k as usize <= scripts.len(),
    )(input)?;

    Ok((input, DescriptorTemplate::Thresh(k, scripts)))
}

fn parse_tr(input: &str) -> IResult<&str, DescriptorTemplate> {
    let (input, key_placeholder) = preceded(tag("tr("), parse_key_placeholder)(input)?;

    let parse_tree = opt(preceded(char(','), parse_tap_tree));

    let (input, tree) = terminated(parse_tree, char(')'))(input)?;

    Ok((input, DescriptorTemplate::Tr(key_placeholder, tree)))
}

fn parse_tap_tree(input: &str) -> IResult<&str, TapTree> {
    let parse_branch = || {
        delimited(
            tag("{"),
            pair(parse_tap_tree, preceded(char(','), parse_tap_tree)),
            tag("}"),
        )
    };

    alt((
        map(parse_descriptor, |descriptor| {
            TapTree::Script(Box::new(descriptor))
        }),
        map(parse_branch(), |(left, right)| {
            TapTree::Branch(Box::new(left), Box::new(right))
        }),
    ))(input)
}

impl FromStr for DescriptorTemplate {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_descriptor_template(input)
    }
}

pub struct WalletPolicy {
    pub name: String,
    pub descriptor_template: DescriptorTemplate,
    pub key_information: Vec<KeyInformation>,

    descriptor_template_raw: String,
    key_information_raw: Vec<String>,
}

impl WalletPolicy {
    pub fn new(
        name: String,
        descriptor_template_str: &str,
        key_information_str: Vec<&str>,
    ) -> Result<Self, &'static str> {
        let descriptor_template = DescriptorTemplate::from_str(descriptor_template_str)
            .map_err(|_| "Failed to parse descriptor template")?;
        let key_information = key_information_str
            .iter()
            .map(|s| parse_key_information(s).finish())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Failed to parse key origin information")?
            .into_iter()
            .map(|(_, k)| k)
            .collect::<Vec<KeyInformation>>();

        let key_information_raw = key_information_str
            .into_iter()
            .map(|s| String::from(s))
            .collect();

        Ok(Self {
            name,
            descriptor_template,
            key_information,
            descriptor_template_raw: String::from(descriptor_template_str),
            key_information_raw,
        })
    }

    pub fn descriptor_template_raw(&self) -> &str {
        &self.descriptor_template_raw
    }

    pub fn key_information_raw(&self) -> impl Iterator<Item = &String> {
        self.key_information_raw.iter()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut res: Vec<u8> = vec![2];
        res.extend_from_slice(&(self.name.len() as u8).to_be_bytes());
        res.extend_from_slice(self.name.as_bytes());
        res.extend(encode::serialize(&VarInt(
            self.descriptor_template_raw.as_bytes().len() as u64,
        )));

        let desc_tmp_hash = CtxSha256::new()
            .update(&self.descriptor_template_raw.as_bytes())
            .r#final();

        res.extend_from_slice(&desc_tmp_hash);

        res.extend(encode::serialize(&VarInt(
            self.key_information_raw.len() as u64
        )));

        res.extend_from_slice(
            MerkleTree::new(
                self.key_information_raw
                    .iter()
                    .map(|key| {
                        CtxSha256::new()
                            .update(&vec![0x00])
                            .update(key.to_string().as_bytes())
                            .r#final()
                    })
                    .collect(),
            )
            .root_hash(),
        );

        res
    }

    pub fn id(&self) -> [u8; 32] {
        CtxSha256::new().update(&self.serialize()).r#final()
    }
}

impl ToDescriptor for TapTree {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, &'static str> {
        match self {
            TapTree::Script(descriptor_template) => {
                descriptor_template.to_descriptor(key_information, is_change, address_index)
            }
            TapTree::Branch(left, right) => {
                let left_descriptor =
                    left.to_descriptor(key_information, is_change, address_index)?;
                let right_descriptor =
                    right.to_descriptor(key_information, is_change, address_index)?;

                Ok(format!("{{{},{}}}", left_descriptor, right_descriptor))
            }
        }
    }
}

impl ToDescriptor for DescriptorTemplate {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, &'static str> {
        // converts a single placeholder to its string expression in a descriptor
        let fmt_kp = |key_placeholder: &KeyPlaceholder,
                      is_change: bool,
                      address_index: u32|
         -> Result<String, &'static str> {
            let key_info = key_information
                .get(key_placeholder.key_index as usize)
                .ok_or("Invalid key index")
                .map(|key_info| key_info.to_string());

            let key_info = key_info?;

            let change_step = if is_change {
                key_placeholder.num1
            } else {
                key_placeholder.num2
            };
            Ok(format!("{}/{}/{}", key_info, change_step, address_index))
        };

        // converts a slice of placeholder to its string expression in a descriptor
        let fmt_kps = |key_placeholders: &[KeyPlaceholder],
                       is_change: bool,
                       address_index: u32|
         -> Result<String, &'static str> {
            Ok(key_placeholders
                .iter()
                .map(|key_placeholder| fmt_kp(key_placeholder, is_change, address_index))
                .collect::<Result<Vec<_>, _>>()?
                .join(","))
        };

        // formats a wrapper
        let fmt_wrapper =
            |wrapper_name: &str, inner: &DescriptorTemplate| -> Result<String, &'static str> {
                let inner_desc = inner.to_descriptor(key_information, is_change, address_index)?;
                if inner.is_wrapper() {
                    Ok(format!("{}{}", wrapper_name, inner_desc))
                } else {
                    Ok(format!("{}:{}", wrapper_name, inner_desc))
                }
            };

        match self {
            DescriptorTemplate::Sh(inner) => {
                let inner_desc = inner.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("sh({})", inner_desc))
            }
            DescriptorTemplate::Wsh(inner) => {
                let inner_desc = inner.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("wsh({})", inner_desc))
            }
            DescriptorTemplate::Pkh(kp) => {
                Ok(format!("pkh({})", fmt_kp(kp, is_change, address_index)?))
            }
            DescriptorTemplate::Wpkh(kp) => {
                Ok(format!("wpkh({})", fmt_kp(kp, is_change, address_index)?))
            }
            DescriptorTemplate::Sortedmulti(threshold, kps) => Ok(format!(
                "sortedmulti({}, {})",
                threshold,
                fmt_kps(kps, is_change, address_index)?
            )),
            DescriptorTemplate::Sortedmulti_a(threshold, kps) => Ok(format!(
                "sortedmulti_a({}, {})",
                threshold,
                fmt_kps(kps, is_change, address_index)?
            )),
            DescriptorTemplate::Tr(kp, tap_tree) => match tap_tree {
                Some(tree) => {
                    let tap_tree_str =
                        tree.to_descriptor(key_information, is_change, address_index)?;
                    Ok(format!(
                        "tr({}, {})",
                        fmt_kp(kp, is_change, address_index)?,
                        tap_tree_str
                    ))
                }
                None => Ok(format!("tr({})", fmt_kp(kp, is_change, address_index)?)),
            },
            DescriptorTemplate::Zero => Ok("0".to_string()),
            DescriptorTemplate::One => Ok("1".to_string()),
            DescriptorTemplate::Pk(kp) => {
                Ok(format!("pk({})", fmt_kp(kp, is_change, address_index)?))
            }
            DescriptorTemplate::Pk_k(kp) => {
                Ok(format!("pk_k({})", fmt_kp(kp, is_change, address_index)?))
            }
            DescriptorTemplate::Pk_h(kp) => {
                Ok(format!("pk_h({})", fmt_kp(kp, is_change, address_index)?))
            }
            DescriptorTemplate::Older(n) => Ok(format!("older({})", n)),
            DescriptorTemplate::After(n) => Ok(format!("after({})", n)),
            DescriptorTemplate::Sha256(hash) => Ok(format!("sha256({})", hex::encode(hash))),
            DescriptorTemplate::Ripemd160(hash) => Ok(format!("ripemd160({})", hex::encode(hash))),
            DescriptorTemplate::Hash256(hash) => Ok(format!("hash256({})", hex::encode(hash))),
            DescriptorTemplate::Hash160(hash) => Ok(format!("hash160({})", hex::encode(hash))),
            DescriptorTemplate::Andor(x, y, z) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let y_descriptor = y.to_descriptor(key_information, is_change, address_index)?;
                let z_descriptor = z.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!(
                    "andor({},{},{})",
                    x_descriptor, y_descriptor, z_descriptor
                ))
            }
            DescriptorTemplate::And_v(x, y) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let y_descriptor = y.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("and_v({},{})", x_descriptor, y_descriptor))
            }
            DescriptorTemplate::And_b(x, y) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let y_descriptor = y.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("and_b({},{})", x_descriptor, y_descriptor))
            }
            DescriptorTemplate::And_n(x, y) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let y_descriptor = y.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("and_n({},{})", x_descriptor, y_descriptor))
            }
            DescriptorTemplate::Or_b(x, z) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let z_descriptor = z.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("or_b({},{})", x_descriptor, z_descriptor))
            }
            DescriptorTemplate::Or_c(x, z) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let z_descriptor = z.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("or_c({},{})", x_descriptor, z_descriptor))
            }
            DescriptorTemplate::Or_d(x, z) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let z_descriptor = z.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("or_d({},{})", x_descriptor, z_descriptor))
            }
            DescriptorTemplate::Or_i(x, z) => {
                let x_descriptor = x.to_descriptor(key_information, is_change, address_index)?;
                let z_descriptor = z.to_descriptor(key_information, is_change, address_index)?;
                Ok(format!("or_i({},{})", x_descriptor, z_descriptor))
            }
            DescriptorTemplate::Thresh(k, sub_templates) => {
                let sub_descriptors: Result<Vec<String>, _> = sub_templates
                    .iter()
                    .map(|template| {
                        template.to_descriptor(key_information, is_change, address_index)
                    })
                    .collect();
                let sub_descriptors = sub_descriptors?;
                Ok(format!("thresh({},[{}])", k, sub_descriptors.join(",")))
            }
            DescriptorTemplate::Multi(threshold, kps) => Ok(format!(
                "multi({}, {})",
                threshold,
                fmt_kps(kps, is_change, address_index)?
            )),
            DescriptorTemplate::Multi_a(threshold, kps) => Ok(format!(
                "multi_a({}, {})",
                threshold,
                fmt_kps(kps, is_change, address_index)?
            )),
            DescriptorTemplate::A(inner) => fmt_wrapper("a", inner),
            DescriptorTemplate::S(inner) => fmt_wrapper("s", inner),
            DescriptorTemplate::C(inner) => fmt_wrapper("c", inner),
            DescriptorTemplate::T(inner) => fmt_wrapper("t", inner),
            DescriptorTemplate::D(inner) => fmt_wrapper("d", inner),
            DescriptorTemplate::V(inner) => fmt_wrapper("v", inner),
            DescriptorTemplate::J(inner) => fmt_wrapper("j", inner),
            DescriptorTemplate::N(inner) => fmt_wrapper("n", inner),
            DescriptorTemplate::L(inner) => fmt_wrapper("l", inner),
            DescriptorTemplate::U(inner) => fmt_wrapper("u", inner),
        }
    }
}

// TODO: add tests for to_descriptor

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    const H: u32 = HARDENED_INDEX;
    const MAX_STEP: &'static str = "2147483647";
    const MAX_STEP_H: &'static str = "2147483647'";

    #[test]
    fn test_parse_derivation_step_number() {
        let test_cases_success = vec![
            ("0", ("", 0)),
            ("0'", ("", H)),
            ("1", ("", 1)),
            ("1'", ("", 1 + H)),
            (MAX_STEP, ("", H - 1)),
            (MAX_STEP_H, ("", H - 1 + H)),
            // only ' is supported as hardened symbol, so this must leave the h or H unparsed
            ("5h", ("h", 5)),
            ("5H", ("H", 5)),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_derivation_step_number(input);
            assert_eq!(result, Ok(expected));
        }

        let test_cases_err = vec!["", "a", stringify!(H), concat!(stringify!(H), "'")];

        for input in test_cases_err {
            assert!(parse_derivation_step_number(input).is_err());
        }
    }

    fn make_key_origin_info(fpr: u32, der_path: Vec<u32>) -> KeyOrigin {
        KeyOrigin {
            fingerprint: fpr,
            derivation_path: der_path,
        }
    }

    #[test]
    fn test_parse_key_origin() {
        let test_cases_success = vec![
            (
                "[012345af/0'/1'/3]",
                ("", make_key_origin_info(0x012345af, vec![0 + H, 1 + H, 3])),
            ),
            (
                "[012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89]",
                (
                    "",
                    make_key_origin_info(
                        0x012345af,
                        vec![2147483647 + H, 1 + H, 3, 6, 7, 42, 12, 54, 23, 56, 89],
                    ),
                ),
            ),
            ("[012345af]", ("", make_key_origin_info(0x012345af, vec![]))),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_key_origin(input);
            assert_eq!(result, Ok(expected));
        }

        let test_cases_err = vec![
            "01234567/0'/1'/3]",
            "[0123456/0'/1'/3]",
            "[012345678/0'/1'/3]",
            "[012345af/00'/1'/3]", // leading zeros not allowed
            "[012345af/0'/01'/3]", // leading zeros not allowed
            "[012345aF/0'/1'/3]",  // lowercase is compulsory
            "[012345af/0h/1h/3]",  // only ' hardened symbol allowed
            "[012345af/0H/1H/3]",  // only ' hardened symbol allowed
            "[012345ag/0'/1'/2147483648]",
        ];

        for input in test_cases_err {
            assert!(parse_key_origin(input).is_err());
        }
    }

    #[test]
    fn test_parse_key_placeholder() {
        let test_cases_success = vec![
            (
                "@0/**",
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
            ),
            (
                "@4294967295/**",
                KeyPlaceholder {
                    key_index: 4294967295,
                    num1: 0,
                    num2: 1,
                },
            ), // u32::MAX
            (
                "@1/<0;1>/*",
                KeyPlaceholder {
                    key_index: 1,
                    num1: 0,
                    num2: 1,
                },
            ),
            (
                "@2/<3;4>/*",
                KeyPlaceholder {
                    key_index: 2,
                    num1: 3,
                    num2: 4,
                },
            ),
            (
                "@3/<1;9>/*",
                KeyPlaceholder {
                    key_index: 3,
                    num1: 1,
                    num2: 9,
                },
            ),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_key_placeholder(input);
            assert_eq!(result, Ok(("", expected)));
        }

        let test_cases_err = vec![
            "@0",
            "@0**",
            "@a/**",
            "@0/*",
            "@0/<0;1>",       // missing /*
            "@0/<0,1>/*",     // , instead of ;
            "@4294967296/**", // too large
            "0/**",
        ];

        for input in test_cases_err {
            assert!(parse_key_placeholder(input).is_err());
        }
    }

    #[test]
    fn test_parse_sortedmulti() {
        let input = "sortedmulti(2,@0/**,@1/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Sortedmulti(
                2,
                vec![
                    KeyPlaceholder {
                        key_index: 0,
                        num1: 0,
                        num2: 1,
                    },
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                ],
            ),
        ));
        assert_eq!(parse_sortedmulti(input), expected);
    }

    #[test]
    fn test_parse_wsh_sortedmulti() {
        let input = "wsh(sortedmulti(2,@0/**,@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Sortedmulti(
                2,
                vec![
                    KeyPlaceholder {
                        key_index: 0,
                        num1: 0,
                        num2: 1,
                    },
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                ],
            ))),
        ));
        assert_eq!(parse_wsh(input), expected);
    }

    #[test]
    fn test_parse_tr() {
        let input = "tr(@0/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
                None,
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        let input = "tr(@0/**,pkh(@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
                Some(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                )))),
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        let input = "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),sh(wpkh(@2/**))})";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 2,
                    num2: 1,
                },
                Some(TapTree::Branch(
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                        KeyPlaceholder {
                            key_index: 1,
                            num1: 2,
                            num2: 7,
                        },
                    )))),
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Sh(Box::new(
                        DescriptorTemplate::Wpkh(KeyPlaceholder {
                            key_index: 2,
                            num1: 0,
                            num2: 1,
                        }),
                    ))))),
                )),
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        // failure cases
        assert!(parse_tr("tr(@0/**,)").is_err());
        assert!(parse_tr("tr(pkh(@0/**))").is_err());
        assert!(parse_tr("tr(@0))").is_err());
        assert!(parse_tr("tr(@0/*))").is_err());
        assert!(parse_tr("tr(@0/*/0)").is_err());
    }

    #[test]
    fn test_parse_valid_descriptor_templates() {
        assert!(parse_descriptor("sln:older(12960)").is_ok());
        assert!(
            parse_thresh("thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960))").is_ok()
        );

        let test_cases = vec![
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        ];

        for input in test_cases {
            let result = parse_descriptor_template(input);
            assert!(result.is_ok())
        }
    }

    #[test]
    fn test_wallet_policy() {
        let wallet = WalletPolicy::new(
            "Cold storage".to_string(),
            &"sh(wsh(sortedmulti(2,@0/**,@1/**)))".to_string(),
            vec![
                "[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
                "[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
            ]
        );

        assert!(wallet.is_ok());
    }

    #[test]
    fn test_wallet_serialize_v2() {
        let wallet = WalletPolicy::new(
            "Cold storage".to_string(),
            &"wsh(sortedmulti(2,@0/**,@1/**))".to_string(),
            vec![
               "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
               "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        ).unwrap();

        assert_eq!(wallet.serialize().encode_hex::<String>(), "020c436f6c642073746f726167651fb56c3d5542fa09b3956834a9ff6a1df5c36a38e5b02c63c54b41a9a04403b82602516d2c50a89476ecffeec658057f0110674bbfafc18797dc480c7ed53802f3fb");
    }
}
