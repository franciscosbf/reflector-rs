use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};
use regex::Regex;
use url::Url;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Sort {
    /// Last server synchronization
    Age,
    /// Download rate
    Rate,
    /// Country name, either alphabetically or in the order given by the --country option
    Country,
    /// Mirror status score
    Score,
    /// Mirror status delay
    Delay,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Protocol {
    Http,
    Https,
    Ftp,
    Rsync,
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Ftp => "ftp",
            Protocol::Rsync => "rsync",
        }
    }
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Inclusive Filters")]
pub struct Filters {
    /// Only return mirrors that have synchronized in the last n hours. n may be an integer or a
    /// decimal number
    #[arg(short, long, value_name = "n", verbatim_doc_comment)]
    pub age: Option<f32>,
    /// Only return mirrors with a reported sync delay of n hours or less, where n is a float. For
    /// example. to limit the results to mirrors with a reported delay of 15 minutes or less, pass
    /// 0.25.
    #[arg(long, value_name = "n", verbatim_doc_comment)]
    pub delay: Option<f32>,
    /// Restrict mirrors to selected countries. Countries may be given by name or country code, or
    /// a mix of both. The case is ignored. Multiple countries may be selected using commas (e.g.
    /// --country France,Germany) or by passing this option multiple times (e.g. -c fr -c de). Use
    /// "--list-countries" to display a table of available countries along with their country codes.
    /// When sorting by country, this option may also be used to sort by a preferred order instead
    /// of alphabetically. For example, to select mirrors from Sweden, Norway, Denmark and Finland,
    /// in that order, use the options "--country se,no,dk,fi --sort country". To set a preferred
    /// country sort order without filtering any countries.  this option also recognizes the glob
    /// pattern "*", which will match any country. For example, to ensure that any mirrors from
    /// Sweden are at the top of the list and any mirrors from Denmark are at the bottom, with any
    /// other countries in between, use "--country 'se,*,dk' --sort country". It is however important
    /// to note that when "*" is given along with other filter criteria, there is no guarantee that
    /// certain countries will be included in the results. For example, with the options "--country
    /// 'se,*,dk' --sort country --latest 10", the latest 10 mirrors may all be from the United
    /// States. When the glob pattern is present, it only ensures that if certain countries are
    /// included in the results, they will be sorted in the requested order
    #[arg(
        short = 'c',
        long = "country",
        value_name = "country name or code",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    pub countries: Option<Vec<String>>,
    /// Return the n fastest mirrors that meet the other criteria. Do not use this option without
    /// other filtering options
    #[arg(short, long, value_name = "n", verbatim_doc_comment)]
    pub fastest: Option<u32>,
    /// Include servers that match <regex>, where <regex> is a Rust regex's crate regular expression
    #[arg(short, long, value_name = "regex", verbatim_doc_comment)]
    pub include: Option<Vec<Regex>>,
    /// Exclude servers that match <regex>, where <regex> is a Rust regex's crate regular expression
    #[arg(short = 'x', long, value_name = "regex", verbatim_doc_comment)]
    pub exclude: Option<Vec<Regex>>,
    /// Limit the list to the n most recently synchronized servers
    #[arg(short, long, value_name = "n")]
    pub latest: Option<u32>,
    /// Limit the list to the n servers with the highest score
    #[arg(long, value_name = "n")]
    pub score: Option<u32>,
    /// Return at most n mirrors
    #[arg(short, long, value_name = "n")]
    pub number: Option<u32>,
    /// Match one of the given protocols, e.g. "https" or "ftp". Multiple protocols may be selected
    /// using commas (e.g. "https,http") or by passing this option multiple times
    #[arg(
        short,
        long,
        value_name = "protocol",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    pub protocol: Option<Vec<String>>,
    /// Set the minimum completion percent for the returned mirrors. Check the mirror status webpage
    /// for the meaning of this parameter
    #[arg(
        long,
        value_name = "[0-100]",
        default_value_t = 100.,
        verbatim_doc_comment
    )]
    pub completion_percent: f32,
    /// Only return mirrors that host ISOs
    #[arg(long)]
    pub isos: bool,
    /// Only return mirrors that support IPv4
    #[arg(long)]
    pub ipv4: bool,
    /// Only return mirrors that support IPv6
    #[arg(long)]
    pub ipv6: bool,
}

/// Retrieve and filter a list of the latest Arch Linux mirrors
///
/// Filters are inclusive, i.e. the returned list will only contain mirrors for which all of the
/// given conditions are met
#[derive(Debug, Parser)]
#[command(version, about, long_about, verbatim_doc_comment)]
pub struct Reflector {
    /// The number of seconds to wait before a connection times out
    #[arg(long, value_name = "n", default_value_t = 5)]
    pub connection_timeout: u32,
    /// The number of seconds to wait before a download times out
    #[arg(long, value_name = "n", default_value_t = 5)]
    pub donwload_timeout: u32,
    /// Display a table of the distribution of servers by country
    #[arg(long)]
    pub list_countries: bool,
    /// The cache timeout in seconds for the data retrieved from the Arch Linux Mirror Status API
    #[arg(long, value_name = "n", default_value_t = 300)]
    pub cache_timeout: u32,
    /// The URL from which to retrieve the mirror data in JSON format. If different from the default,
    /// it must follow the same format
    #[arg(
        long,
        value_name = "mirrors url",
        default_value = "https://archlinux.org/mirrors/status/json/",
        verbatim_doc_comment
    )]
    pub url: Url,
    /// Save the mirrorlist to the given path.
    #[arg(long, value_name = "file path")]
    pub save: Option<PathBuf>,
    /// Sort the mirrorlist
    #[arg(long, value_name = "sort", value_enum)]
    pub sort: Option<Sort>,
    /// Use n threads for rating mirrors. This option will speed up the rating step but the results
    /// will be inaccurate if the local bandwidth is saturated at any point during the operation.
    /// If rating takes too long without this option then you should probably apply more filters to
    /// reduce the number of rated servers before using this option
    #[arg(long, value_name = "n", default_value_t = 0, verbatim_doc_comment)]
    pub threads: u32,
    /// Print extra information to standard error. Only works with some options
    #[arg(long)]
    pub verbose: bool,
    /// Print mirror information instead of a mirror list. Filter options apply
    #[arg(long)]
    pub info: bool,
    #[clap(flatten)]
    pub filters: Filters,
}
