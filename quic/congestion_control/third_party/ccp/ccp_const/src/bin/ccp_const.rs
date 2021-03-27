extern crate ccp_const;
extern crate clap;
extern crate portus;
extern crate slog;

use ccp_const::CcpConstAlg;
use clap::Arg;
use slog::warn;

const MBPS_TO_BPS: u32 = 1_000_000;
const BITS_TO_BYTES: u32 = 8;
const PKTS_TO_BYTES: u32 = 1500;
fn main() {
    let log = portus::algs::make_logger();

    let (cfg, ipc) = || -> Result<(CcpConstAlg, String), String> {
        let matches = clap::App::new("CCP Constant Cwnd/Rate")
            .version("0.1.0")
            .author("<ccp@csail.mit.edu>")
            .about("Congestion control algorithm which sets a constant rate or cwnd")
            .arg(
                Arg::with_name("ipc")
                    .long("ipc")
                    .help("Sets the type of ipc to use: (netlink|unix)")
                    .takes_value(true)
                    .required(true)
                    .validator(portus::algs::ipc_valid),
            )
            .arg(
                Arg::with_name("cwnd")
                    .long("cwnd")
                    .takes_value(true)
                    .help("Sets the congestion window, in packets."),
            )
            .arg(
                Arg::with_name("rate")
                    .long("rate")
                    .takes_value(true)
                    .help("Sets the rate to use, in Mbps, must also specify cwnd_cap"),
            )
            .arg(
                Arg::with_name("cwnd_cap")
                    .long("cwnd_cap")
                    .takes_value(true)
                    .help("The max cwnd, in packets, *only* when setting a rate"),
            )
            .group(
                clap::ArgGroup::with_name("to_set")
                    .args(&["cwnd", "rate"])
                    .required(true),
            )
            .get_matches();

        if !matches.is_present("to_set") {
            return Err(String::from("must supply either cwnd or rate"));
        }

        let const_param = if matches.is_present("rate") {
            let rate = u32::from_str_radix(matches.value_of("rate").unwrap(), 10)
                .map_err(|e| format!("{:?}", e))?;
            if !matches.is_present("cwnd_cap") {
                return Err(String::from("when using rate, must also specify cwnd_cap"));
            }
            let cwnd_cap = u32::from_str_radix(matches.value_of("cwnd_cap").unwrap(), 10)
                .map_err(|e| format!("{:?}", e))?;

            let rate = rate * MBPS_TO_BPS / BITS_TO_BYTES;
            let cwnd_cap = cwnd_cap * PKTS_TO_BYTES;
            Ok(ccp_const::Constant::Rate { rate, cwnd_cap })
        } else if matches.is_present("cwnd") {
            let cwnd = u32::from_str_radix(matches.value_of("cwnd").unwrap(), 10)
                .map_err(|e| format!("{:?}", e))?;
            let cwnd = cwnd * PKTS_TO_BYTES;
            Ok(ccp_const::Constant::Cwnd(cwnd))
        } else {
            Err(String::from("must supply either cwnd or rate"))
        }?;

        Ok((
            CcpConstAlg {
                logger: Some(log.clone()),
                const_param,
            },
            String::from(matches.value_of("ipc").unwrap()),
        ))
    }()
    .map_err(|e| warn!(log, "bad argument"; "err" => ?e))
    .unwrap();

    portus::start!(ipc.as_str(), Some(log), cfg).unwrap()
}
