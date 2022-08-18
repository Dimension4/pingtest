use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use async_std::{fs::write, task};
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use serde::Serialize;
use tabled::{Style, Table, Tabled};
use winping::{AsyncPinger, Buffer};

#[derive(Serialize)]
struct Report {
    start_time: String,
    duration: u32,
    interval: u32,
    targets: Vec<TargetReport>,
}

#[derive(Serialize)]
struct TargetReport {
    host_name: String,
    ip: String,
    pings: Vec<PingResult>,
}

#[derive(Serialize, Clone)]
struct PingResult {
    started_at: u32,
    rtt: u32,
}

#[derive(Debug, Clone)]
struct Target {
    ip: IpAddr,
    host: Option<String>,
}

impl ToString for Target {
    fn to_string(&self) -> String {
        match self.host.as_deref() {
            Some(name) => format!("{name} ({})", self.ip),
            None => self.ip.to_string(),
        }
    }
}

fn resolve_target(s: &str) -> Result<Target, String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        if let Ok(name) = lookup_addr(&ip) {
            if let Err(_) = name.parse::<IpAddr>() {
                // sometimes the IP is returned as host name
                return Ok(Target {
                    ip,
                    host: Some(name.into()),
                });
            }
        }
        return Ok(Target { ip, host: None });
    } else {
        if let Ok(ips) = lookup_host(&s).as_deref() {
            if let Some(&ip) = ips.iter().find(|&&ip| ip.is_ipv4()).or(ips.first()) {
                return Ok(Target {
                    ip,
                    host: Some(s.into()),
                });
            }
        }
        Err(format!("'{s}' is not a valid IP or host name"))
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interval between two pings in ms.
    #[clap(short, long, default_value_t = 500)]
    interval: u32,

    /// Total run time (for how long to ping targets) in s.
    #[clap(short, long, default_value_t = 30)]
    duration: u32,

    /// Timeout for each ping.
    #[clap(short, long, default_value_t = 1000)]
    timeout: u32,

    /// Output directory in which the report will be generated. A unique filename will be generated.
    #[clap(short, long)]
    out_dir: Option<PathBuf>,

    /// Output file in which to write the report. This option overwrites --out-dir.
    #[clap(long)]
    out_file: Option<PathBuf>,

    /// Prints an introduction to stdout.
    #[clap(long, value_parser, default_value_t = true)]
    display_intro: bool,

    /// Prints a summary to stdout.
    #[clap(long, value_parser, default_value_t = true)]
    display_summary: bool,

    /// Prints each ping result to stdout.
    #[clap(long, value_parser)]
    display_pings: bool,

    /// List of targets to ping. Each target can be an IP or host name.
    #[clap(value_parser=resolve_target)]
    ips_or_host_names: Vec<Target>,
}

#[async_std::main]
async fn main() {
    let args = Args::parse();

    if args.display_intro {
        display_intro(&args);
    }

    let mut out_file = None;

    if args.out_dir.is_some() || args.out_file.is_some() {
        match resolve_out_file(&args) {
            Ok(p) => out_file = Some(p),
            Err(e) => {
                println!("{e}");
                return;
            }
        }
    }

    let report = run(&args).await;

    if let Some(p) = &out_file {
        let json = serde_json::to_string_pretty(&report).unwrap();
        _ = write(p, json).await;
    }

    if args.display_summary {
        display_summary(&report);
    }
}

fn display_summary(report: &Report) {
    #[derive(Tabled)]
    #[tabled(rename_all = "PascalCase")]
    struct Stats<'s> {
        #[tabled(rename = "IP")]
        ip: &'s str,
        host: &'s str,
        pings: u32,
        #[tabled(rename = "Packet Loss")]
        packet_loss: String,
        min: String,
        median: String,
        #[tabled(rename = "95% Percentile")]
        per95: String,
        max: String,
    }

    fn compute_stats(t: &TargetReport) -> Stats {
        let mut pings: Vec<u32> = t.pings.iter().map(|p| p.rtt).collect();
        pings.sort();
        pings.push(u32::MAX); // add a fake timeout entry so we can use partition_point
        let idx = pings.partition_point(|&p| p < u32::MAX);
        let in_time = &pings[..idx];
        let ping_count = (pings.len() - 1) as u32;

        if in_time.is_empty() {
            Stats {
                ip: &t.ip,
                host: &t.host_name,
                pings: ping_count,
                packet_loss: "100.00 %".into(),
                min: "-".into(),
                median: "-".into(),
                per95: "-".into(),
                max: "-".into(),
            }
        } else {
            Stats {
                ip: &t.ip,
                host: &t.host_name,
                pings: ping_count,
                packet_loss: format!("{:>6.2} %", 1.0 - in_time.len() as f32 / ping_count as f32),
                min: format!("{:>4} ms", in_time[0]),
                median: format!("{:>4} ms", in_time[in_time.len() / 2]),
                per95: format!("{:>4} ms", in_time[(in_time.len() as f64 * 0.95) as usize]),
                max: format!("{:>4} ms", in_time[in_time.len() - 1]),
            }
        }
    }

    let stats: Vec<_> = report.targets.iter().map(compute_stats).collect();
    let table = Table::new(&stats).with(Style::modern());

    println!("{table}");
}

fn display_intro(args: &Args) {
    println!(
        "Pinging {} target(s) every {}ms for the next {}s:",
        args.ips_or_host_names.len(),
        args.interval,
        args.duration
    );

    for target in &args.ips_or_host_names {
        println!("    {}", target.to_string())
    }
}

fn resolve_out_file(args: &Args) -> Result<PathBuf, String> {
    if let Some(file) = &args.out_file {
        if file.is_file() {
            Err(format!("File '{}' already exists.", file.display()))
        } else if file.is_dir() {
            Err(format!("'{}' is a directory.", file.display()))
        } else {
            Ok(file.clone())
        }
    } else {
        if let Some(dir) = &args.out_dir {
            if dir.is_dir() {
                let now = chrono::Local::now();
                let name = dir.join(now.format("pings_%F_%H-%M-%S.json").to_string());
                if name.exists() {
                    Err("Unable to generate file name. Use --out-file to explicitly specify a file path.".into())
                } else {
                    Ok(name)
                }
            } else if dir.is_file() {
                Err(format!("'{}' is a file.", dir.display()))
            } else {
                Err(format!("Directory '{}' doesn't exist.", dir.display()))
            }
        } else {
            Err("Unable to resolve out file".into())
        }
    }
}

async fn run(args: &Args) -> Report {
    let system_time = chrono::Local::now();
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(args.duration.into());
    let interval = Duration::from_millis(args.interval as u64);
    let mut pinger = AsyncPinger::new();
    pinger.set_timeout(args.timeout);

    let tasks = args.ips_or_host_names.iter().map(|t| {
        ping_target(
            &pinger,
            t,
            &interval,
            &start_time,
            &end_time,
            args.display_pings,
        )
    });

    let targets = futures::future::join_all(tasks).await;

    Report {
        start_time: system_time.to_rfc3339(),
        duration: args.duration,
        interval: args.interval,
        targets,
    }
}

async fn ping_target(
    pinger: &AsyncPinger,
    target: &Target,
    interval: &Duration,
    start_time: &Instant,
    end_time: &Instant,
    display_pings: bool,
) -> TargetReport {
    let mut pings: Vec<PingResult> = Vec::new();
    let name = if display_pings {
        Some(format!("{:>15}", target.ip))
    } else {
        None
    };

    loop {
        let now = Instant::now();
        if now >= *end_time {
            break;
        }

        let started_at = now.duration_since(*start_time).as_millis() as u32;

        let ping = match pinger.send(target.ip, Buffer::new()).await.result {
            Ok(rtt) => PingResult { started_at, rtt },
            Err(_) => PingResult {
                started_at,
                rtt: u32::MAX,
            },
        };

        if let Some(n) = &name {
            println!("Reply from {n}: {:>4} ms", ping.rtt);
        }

        pings.push(ping);

        let remaining = now + *interval - Instant::now();

        if !remaining.is_zero() {
            task::sleep(remaining).await;
        }
    }

    TargetReport {
        host_name: target.host.clone().unwrap_or_default(),
        ip: target.ip.to_string(),
        pings,
    }
}
