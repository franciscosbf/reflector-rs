#![allow(dead_code)]

use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use base64::{Engine, prelude::BASE64_URL_SAFE};
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{Args, Parser, ValueEnum};
use expanduser::expanduser;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use url::Url;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");

const DEFAULT_MIRRORS_URL: &str = "https://archlinux.org/mirrors/status/json/";

const PARSE_TIME_FORMAT_WITH_USEC: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";
const PARSE_TIME_FORMAT_WITHOUT_USEC: &str = "%Y-%m-%dT%H:%M:%SZ";

const XDG_CACHE_HOME: &str = "XDG_CACHE_HOME";
const DEFAULT_CACHE_DIR: &str = "~/.cache";

const DB_SUBPATH: &str = "extra/os/x86_64/extra.db";

const DEFAULT_CONNECTION_TIMEOUT: u64 = 5;
const DEFAULT_DOWNLOAD_TIMEOUT: u64 = 5;
const DEFAULT_CACHE_TIMEOUT: u64 = 300;

const ONE_HOUR_IN_SECS: f64 = 3600.;

#[derive(Debug, Error)]
pub enum ReflectorError {
    #[error(transparent)]
    RetrieveMirrorsFailed(#[from] reqwest::Error),
    #[error("without mirrors")]
    WithoutMirrors,
    #[error(transparent)]
    WriteMirrorsFailed(#[from] io::Error),
}

fn deserialize_url<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
    let raw = <&str>::deserialize(deserializer)?;

    Url::parse(raw).map_err(de::Error::custom)
}

fn serialize_url<S: Serializer>(url: &Url, serializer: S) -> Result<S::Ok, S::Error> {
    let raw = url.as_str();

    serializer.serialize_str(raw)
}

fn deserialize_datetime_without_usec<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error> {
    let raw = match <Option<&str>>::deserialize(deserializer)? {
        Some(raw) => raw,
        None => return Ok(None),
    };

    NaiveDateTime::parse_from_str(raw, PARSE_TIME_FORMAT_WITHOUT_USEC)
        .map(|ndt| Some(ndt.and_utc()))
        .map_err(de::Error::custom)
}

fn serialize_datetime_without_usec<S: Serializer>(
    datetime: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match datetime {
        Some(datetime) => {
            let raw = format!("{}", datetime.format(PARSE_TIME_FORMAT_WITHOUT_USEC));

            serializer.serialize_some(&raw)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_datetime_with_usec<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
    let raw = <&str>::deserialize(deserializer)?;

    NaiveDateTime::parse_from_str(raw, PARSE_TIME_FORMAT_WITH_USEC)
        .map(|ndt| ndt.and_utc())
        .map_err(de::Error::custom)
}

fn serialize_datetime_with_usec<S: Serializer>(
    datetime: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let raw = format!("{}", datetime.format(PARSE_TIME_FORMAT_WITH_USEC));

    serializer.serialize_str(&raw)
}

fn parse_uppercase_country(s: &str) -> Result<String, String> {
    let raw = s.to_uppercase();

    Ok(raw)
}

fn parse_percentage(s: &str) -> Result<f64, String> {
    let raw = s.parse::<f64>().map_err(|err| err.to_string())?;

    if (0_f64..=100_f64).contains(&raw) {
        Ok(raw)
    } else {
        Err("must be between 0 and 100".to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ValueEnum, Hash)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Http,
    Https,
    Ftp,
    Rsync,
}

#[derive(Debug, Deserialize, Serialize)]
struct MirrorStatus {
    #[serde(deserialize_with = "deserialize_url", serialize_with = "serialize_url")]
    url: Url,
    protocol: Protocol,
    #[serde(
        deserialize_with = "deserialize_datetime_without_usec",
        serialize_with = "serialize_datetime_without_usec"
    )]
    last_sync: Option<DateTime<Utc>>,
    completion_pct: f64,
    delay: Option<u64>,
    score: Option<f64>,
    active: bool,
    country: String,
    country_code: String,
    isos: bool,
    ipv4: bool,
    ipv6: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Status {
    #[serde(
        deserialize_with = "deserialize_datetime_with_usec",
        serialize_with = "serialize_datetime_with_usec"
    )]
    last_check: DateTime<Utc>,
    urls: Vec<MirrorStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Sort {
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

#[derive(Debug, Args)]
#[command(next_help_heading = "Inclusive Filters")]
struct Filters {
    /// Only return mirrors that have synchronized in the last n hours. n may be an integer or a
    /// decimal number
    #[arg(short, long, value_name = "n", verbatim_doc_comment)]
    age: Option<f64>,
    /// Only return mirrors with a reported sync delay of n hours or less, where n is a float. For
    /// example. to limit the results to mirrors with a reported delay of 15 minutes or less, pass
    /// 0.25.
    #[arg(long, value_name = "n", verbatim_doc_comment)]
    delay: Option<f64>,
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
        value_parser = parse_uppercase_country,
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    countries: Option<Vec<String>>,
    /// Return the n fastest mirrors that meet the other criteria. Do not use this option without
    /// other filtering options
    #[arg(short, long, value_name = "n", verbatim_doc_comment)]
    fastest: Option<u64>,
    /// Include servers that match <regex>, where <regex> is a Rust regex's crate regular expression
    #[arg(short, long, value_name = "regex", verbatim_doc_comment)]
    include: Option<Vec<Regex>>,
    /// Exclude servers that match <regex>, where <regex> is a Rust regex's crate regular expression
    #[arg(short = 'x', long, value_name = "regex", verbatim_doc_comment)]
    exclude: Option<Vec<Regex>>,
    /// Limit the list to the n most recently synchronized servers
    #[arg(short, long, value_name = "n")]
    latest: Option<u64>,
    /// Limit the list to the n servers with the highest score
    #[arg(long, value_name = "n")]
    score: Option<u64>,
    /// Return at most n mirrors
    #[arg(short, long, value_name = "n")]
    number: Option<u64>,
    /// Match one of the given protocols, e.g. "https" or "ftp". Multiple protocols may be selected
    /// using commas (e.g. "https,http") or by passing this option multiple times
    #[arg(
        short,
        long = "protocol",
        value_name = "protocol",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    protocols: Option<Vec<Protocol>>,
    /// Set the minimum completion percent for the returned mirrors. Check the mirror status webpage
    /// for the meaning of this parameter
    #[arg(
        long,
        value_name = "0-100",
        value_parser = parse_percentage,
        default_value_t = 100.,
        verbatim_doc_comment
    )]
    completion_percent: f64,
    /// Only return mirrors that host ISOs
    #[arg(long)]
    isos: bool,
    /// Only return mirrors that support IPv4
    #[arg(long)]
    ipv4: bool,
    /// Only return mirrors that support IPv6
    #[arg(long)]
    ipv6: bool,
}

/// Retrieve and filter a list of the latest Arch Linux mirrors
///
/// Filters are inclusive, i.e. the returned list will only contain mirrors for which all of the given
/// conditions are met
#[derive(Debug, Parser)]
#[command(version, about, long_about, verbatim_doc_comment)]
struct Reflector {
    /// The number of seconds to wait before a connection times out
    #[arg(long, value_name = "n", default_value_t = DEFAULT_CONNECTION_TIMEOUT)]
    connection_timeout: u64,
    /// The number of seconds to wait before a download times out
    #[arg(long, value_name = "n", default_value_t = DEFAULT_DOWNLOAD_TIMEOUT)]
    download_timeout: u64,
    /// Display a table of the distribution of servers by country
    #[arg(long)]
    list_countries: bool,
    /// The cache timeout in seconds for the data retrieved from the Arch Linux Mirror Status API
    #[arg(long, value_name = "n", default_value_t = DEFAULT_CACHE_TIMEOUT)]
    cache_timeout: u64,
    /// The URL from which to retrieve the mirror data in JSON format. If different from the default,
    /// it must follow the same format
    #[arg(
        long,
        value_name = "mirrors url",
        default_value = "https://archlinux.org/mirrors/status/json/",
        verbatim_doc_comment
    )]
    url: Url,
    /// Save the mirrorlist to the given path.
    #[arg(long, value_name = "file path")]
    save: Option<PathBuf>,
    /// Sort the mirrorlist
    #[arg(long, value_name = "sort", value_enum)]
    sort: Option<Sort>,
    /// Use n threads for rating mirrors. This option will speed up the rating step but the results
    /// will be inaccurate if the local bandwidth is saturated at any point during the operation.
    /// If rating takes too long without this option then you should probably apply more filters to
    /// reduce the number of rated servers before using this option
    #[arg(long, value_name = "n", default_value_t = 0, verbatim_doc_comment)]
    threads: u64,
    /// Print extra information to standard error. Only works with some options
    #[arg(long)]
    verbose: bool,
    /// Print mirror information instead of a mirror list. Filter options apply
    #[arg(long)]
    info: bool,
    #[clap(flatten)]
    filters: Filters,
}

fn initialize_logger(verbose: bool) {
    let colored_level = ColoredLevelConfig::new()
        .warn(Color::Yellow)
        .info(Color::Green);

    fern::Dispatch::new()
        .filter(move |metadata| verbose || metadata.level() == LevelFilter::Info)
        .chain(io::stdout())
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}] [{}] [{}] {}",
                humantime::format_rfc3339_millis(SystemTime::now()),
                colored_level.color(record.level()),
                PKG_NAME,
                message
            ));
        })
        .apply()
        .unwrap();
}

fn cached_status(location: &Path, timeout: Duration) -> Result<Option<Status>, anyhow::Error> {
    let mut file = File::open(location)?;
    let modified = file.metadata()?.modified()?;

    let valid = SystemTime::now().duration_since(modified).unwrap() <= timeout;
    let status = if valid {
        let mut raw = vec![];
        file.read_to_end(&mut raw)?;

        serde_json::from_slice(&raw)?
    } else {
        None
    };

    Ok(status)
}

fn cache_status(location: &Path, status: &Status) -> Result<(), io::Error> {
    let raw = serde_json::to_vec(status).unwrap();

    fs::write(location, raw)
}

fn retrieve_status(reflector: &Reflector) -> Result<Status, ReflectorError> {
    let cache_dir = match env::var(XDG_CACHE_HOME) {
        Ok(cache) => PathBuf::from(cache),
        Err(_) => expanduser(DEFAULT_CACHE_DIR).unwrap(),
    };
    let cache_file = format!(
        "{}-{}.json",
        PKG_NAME,
        BASE64_URL_SAFE.encode(reflector.url.as_str().as_bytes())
    );
    let cache_location = cache_dir.join(cache_file);
    let cache_timeout = Duration::from_secs(reflector.cache_timeout);

    match cached_status(&cache_location, cache_timeout) {
        Ok(Some(status)) => {
            log::info!("Retrieved mirror status from cached file");

            return Ok(status);
        }
        Ok(None) => {}
        Err(err) => {
            log::warn!("Failed to read cached mirrors: {}", err);
        }
    }

    let mirrors_url = reflector.url.as_str();
    let status = reqwest::blocking::get(mirrors_url)?.json()?;

    if let Err(error) = cache_status(&cache_location, &status) {
        log::warn!("Failed to cache mirrors: {}", error);
    }

    log::info!("Retrieved mirrors from {mirrors_url}");

    Ok(status)
}

fn filter_mirrors<'s>(filters: &Filters, status: &'s Status) -> Vec<&'s MirrorStatus> {
    let mut closures: Vec<Box<dyn Fn(&'s MirrorStatus) -> bool>> = vec![];
    let mut add_closure = |filter| closures.push(filter);

    let min_completion_pct = filters.completion_percent / 100.;
    add_closure(Box::new(move |m| {
        m.completion_pct >= min_completion_pct
            && m.last_sync.is_some()
            && m.delay.is_some()
            && m.score.is_some()
    }));

    if let Some(ref countries) = filters.countries {
        let countries = countries.iter().collect::<HashSet<_>>();

        add_closure(Box::new(move |m| {
            countries.contains(&m.country.to_uppercase())
                || countries.contains(&m.country_code.to_uppercase())
        }));
    }

    if let Some(ref protocols) = filters.protocols {
        let protocols = protocols.iter().cloned().collect::<HashSet<_>>();

        add_closure(Box::new(move |m| protocols.contains(&m.protocol)));
    }

    if let Some(ref include) = filters.include {
        add_closure(Box::new(move |m| {
            include.iter().any(|r| r.is_match(m.url.as_str()))
        }));
    }

    if let Some(ref exclude) = filters.exclude {
        add_closure(Box::new(move |m| {
            !exclude.iter().any(|r| r.is_match(m.url.as_str()))
        }));
    }

    if let Some(age) = filters.age {
        let now = SystemTime::now();
        let age = Duration::from_secs_f64(age * ONE_HOUR_IN_SECS);

        add_closure(Box::new(move |m| {
            SystemTime::from(m.last_sync.unwrap()) >= now.checked_sub(age).unwrap()
        }));
    }

    if let Some(delay) = filters.delay {
        let delay = delay * ONE_HOUR_IN_SECS;

        add_closure(Box::new(move |m| m.delay.unwrap() as f64 <= delay));
    }

    if filters.isos {
        add_closure(Box::new(|m| m.isos));
    }

    if filters.ipv4 {
        add_closure(Box::new(|m| m.ipv4));
    }

    if filters.ipv6 {
        add_closure(Box::new(|m| m.ipv6));
    }

    status
        .urls
        .iter()
        .filter(|m| closures.iter().all(|f| f(m)))
        .collect()
}

fn sort_by_age(mirrors: &mut [&MirrorStatus]) {
    mirrors.sort_by(|a, b| {
        let a = a.last_sync.unwrap();
        let b = b.last_sync.unwrap();

        b.cmp(&a)
    });
}

fn sort_by_score(mirrors: &mut [&MirrorStatus]) {
    mirrors.sort_by(|a, b| {
        let a = a.score.unwrap();
        let b = b.score.unwrap();

        a.partial_cmp(&b).unwrap()
    });
}

fn sort_by_rate(
    mirrors: &mut [&MirrorStatus],
    connection_timeout: Duration,
    download_timeout: Duration,
) {
    let _ = mirrors;
    let _ = connection_timeout;
    let _ = download_timeout;

    todo!()
}

fn sort_by_country_priorities(mirrors: &mut [&MirrorStatus], priority_countries: &[String]) {
    let priority_countries_pos = |c: &str| priority_countries.iter().position(|pc| pc == c);
    let default_priority_country = priority_countries
        .iter()
        .position(|pc| pc == "*")
        .unwrap_or(priority_countries.len());
    let priority_pair = |m: &MirrorStatus| {
        let mc = m.country.to_uppercase();
        if let Some(pos) = priority_countries_pos(mc.as_str()) {
            return (pos, mc);
        }

        let mcc = m.country_code.to_uppercase();
        if let Some(pos) = priority_countries_pos(mcc.as_str()) {
            return (pos, mc);
        }

        (default_priority_country, mc)
    };

    mirrors.sort_by(move |a, b| {
        let a = priority_pair(a);
        let b = priority_pair(b);

        a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1))
    });
}

fn sort_by_country_simple(mirrors: &mut [&MirrorStatus]) {
    mirrors.sort_by(|a, b| {
        let a = a.country.to_uppercase();
        let b = b.country.to_uppercase();

        a.cmp(&b)
    });
}

fn sort_by_country(mirrors: &mut [&MirrorStatus], countries: Option<&Vec<String>>) {
    countries
        .map(|countries| sort_by_country_priorities(mirrors, countries))
        .unwrap_or_else(|| sort_by_country_simple(mirrors));
}

fn sort_by_delay(mirrors: &mut [&MirrorStatus]) {
    mirrors.sort_by(|a, b| {
        let a = a.delay.unwrap();
        let b = b.delay.unwrap();

        a.cmp(&b)
    });
}

fn sort_mirrors(reflector: &Reflector, mirrors: &mut Vec<&MirrorStatus>) {
    let filters = &reflector.filters;
    let connection_timeout = Duration::from_secs(reflector.connection_timeout);
    let download_timeout = Duration::from_secs(reflector.download_timeout);

    match filters.latest {
        Some(latest) if latest > 0 => {
            sort_by_age(mirrors);
            mirrors.truncate(latest as usize);
        }
        _ => (),
    }

    match filters.score {
        Some(score) if score > 0 => {
            sort_by_score(mirrors);
            mirrors.truncate(score as usize);
        }
        _ => (),
    }

    match filters.fastest {
        Some(fastest) if fastest > 0 => {
            sort_by_rate(mirrors, connection_timeout, download_timeout);
            mirrors.truncate(fastest as usize);
        }
        _ => (),
    }

    match reflector.sort {
        Some(sort) if !(sort == Sort::Rate && filters.fastest.is_some()) => match sort {
            Sort::Age => sort_by_age(mirrors),
            Sort::Rate => sort_by_rate(mirrors, connection_timeout, download_timeout),
            Sort::Country => sort_by_country(mirrors, filters.countries.as_ref()),
            Sort::Score => sort_by_score(mirrors),
            Sort::Delay => sort_by_delay(mirrors),
        },
        _ => (),
    }

    if let Some(number) = filters.number {
        mirrors.truncate(number as usize);
    }
}

fn process_mirrors<'s>(
    reflector: &Reflector,
    status: &'s Status,
) -> Result<Vec<&'s MirrorStatus>, ReflectorError> {
    let mut mirrors = filter_mirrors(&reflector.filters, status);
    if mirrors.is_empty() {
        return Err(ReflectorError::WithoutMirrors);
    }

    sort_mirrors(reflector, &mut mirrors);
    if mirrors.is_empty() {
        return Err(ReflectorError::WithoutMirrors);
    }

    Ok(mirrors)
}

fn output_countries(mirrors: &[MirrorStatus]) {
    let _ = mirrors;

    todo!()
}

fn output_mirrors(mirrors: &[&MirrorStatus]) {
    let _ = mirrors;

    todo!()
}

fn record_mirrors(mirrors: &[&MirrorStatus], location: &Path) -> Result<(), ReflectorError> {
    let _ = mirrors;
    let _ = location;

    todo!()
}

fn main() -> anyhow::Result<()> {
    let reflector = Reflector::parse();

    initialize_logger(reflector.verbose);

    let status = retrieve_status(&reflector).context("failed to retrieve mirrors")?;

    if reflector.list_countries {
        output_countries(&status.urls);

        return Ok(());
    }

    let mirrors =
        process_mirrors(&reflector, &status).context("failed to process retrieved mirrors")?;

    if let Some(ref save) = reflector.save {
        record_mirrors(&mirrors, save).context("failed to write mirrors")?;
    } else {
        output_mirrors(&mirrors);
    }

    Ok(())
}
