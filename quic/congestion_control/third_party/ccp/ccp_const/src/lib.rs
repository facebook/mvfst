extern crate clap;
extern crate portus;
extern crate portus_export;
extern crate slog;

use portus::ipc::Ipc;
use portus::lang::Scope;
use portus::{CongAlg, CongAlgBuilder, Datapath, DatapathInfo, DatapathTrait, Report};
use slog::{debug, warn};
use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum Constant {
    Cwnd(u32),
    Rate { rate: u32, cwnd_cap: u32 },
}

#[portus_export::register_ccp_alg]
pub struct CcpConstAlg {
    pub logger: Option<slog::Logger>,
    pub const_param: Constant,
}

pub struct CcpConstFlow<T: Ipc> {
    logger: Option<slog::Logger>,
    sc: Scope,
    control_channel: Datapath<T>,
    const_param: Constant,
    mss: u32,
}

impl<I: Ipc> CongAlg<I> for CcpConstAlg {
    type Flow = CcpConstFlow<I>;

    fn name() -> &'static str {
        "constant"
    }

    fn datapath_programs(&self) -> HashMap<&'static str, String> {
        let mut h = HashMap::default();
        h.insert(
            "constant",
            "
            (def (Report
                (volatile rtt 0)
                (volatile rin 0)
                (volatile rout 0)
                (volatile loss 0)
            ))
            (when true
                (:= Report.rtt Flow.rtt_sample_us)
                (:= Report.rin Flow.rate_outgoing)
                (:= Report.rout Flow.rate_incoming)
                (:= Report.loss (+ Report.loss Ack.lost_pkts_sample))
                (fallthrough)
            )
            (when (> Micros 1000000)
                (report)
                (:= Micros 0)
            )"
            .to_owned(),
        );

        h
    }

    fn new_flow(&self, mut control: Datapath<I>, info: DatapathInfo) -> Self::Flow {
        let params = match self.const_param {
            Constant::Cwnd(c) => vec![("Cwnd", c * info.mss)],
            Constant::Rate {
                rate: r,
                cwnd_cap: c,
            } => vec![("Cwnd", c * info.mss), ("Rate", r)],
        };
        let sc = control.set_program("constant", Some(&params)).unwrap();
        CcpConstFlow {
            logger: self.logger.clone(),
            sc,
            control_channel: control,
            const_param: self.const_param,
            mss: info.mss,
        }
    }
}

use clap::Arg;
const MBPS_TO_BPS: u32 = 1_000_000;
const BITS_TO_BYTES: u32 = 8;
//const PKTS_TO_BYTES: u32 = 1500;
impl<'a, 'b> CongAlgBuilder<'a, 'b> for CcpConstAlg {
    fn args() -> clap::App<'a, 'b> {
        clap::App::new("CCP Constant Cwnd/Rate")
            .version("0.2.0")
            .author("<ccp@csail.mit.edu>")
            .about("Congestion control algorithm which sets a constant rate or cwnd")
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
                    .help("The max cwnd, in MSS packets, *only* when setting a rate"),
            )
            .group(
                clap::ArgGroup::with_name("to_set")
                    .args(&["cwnd", "rate"])
                    .required(true),
            )
    }

    fn with_arg_matches(
        args: &clap::ArgMatches,
        logger: Option<slog::Logger>,
    ) -> Result<Self, portus::Error> {
        if !args.is_present("to_set") {
            return Err(portus::Error(String::from(
                "must supply either cwnd or rate",
            )));
        }

        let const_param = if args.is_present("rate") {
            let rate = u32::from_str_radix(args.value_of("rate").unwrap(), 10)
                .map_err(|e| portus::Error(e.to_string()))?;
            if !args.is_present("cwnd_cap") {
                return Err(portus::Error(String::from(
                    "when using rate, must also specify cwnd_cap",
                )));
            }
            let cwnd_cap = u32::from_str_radix(args.value_of("cwnd_cap").unwrap(), 10)
                .map_err(|e| portus::Error(e.to_string()))?;

            let rate = rate * MBPS_TO_BPS / BITS_TO_BYTES;
            let cwnd_cap = cwnd_cap;
            Ok(Constant::Rate { rate, cwnd_cap })
        } else if args.is_present("cwnd") {
            let cwnd = u32::from_str_radix(args.value_of("cwnd").unwrap(), 10)
                .map_err(|e| portus::Error(e.to_string()))?;
            let cwnd = cwnd;
            Ok(Constant::Cwnd(cwnd))
        } else {
            Err(portus::Error(String::from(
                "must supply either cwnd or rate",
            )))
        }?;

        Ok(Self {
            logger,
            const_param,
        })
    }
}

impl<T: Ipc> portus::Flow for CcpConstFlow<T> {
    fn on_report(&mut self, sock_id: u32, m: Report) {
        let rtt = m
            .get_field("Report.rtt", &self.sc)
            .expect("expected rtt in report") as u32;
        let rin = m
            .get_field("Report.rin", &self.sc)
            .expect("expected rin in report") as u32;
        let rout = m
            .get_field("Report.rout", &self.sc)
            .expect("expected rout in report") as u32;
        let loss = m
            .get_field("Report.loss", &self.sc)
            .expect("expected loss in report") as u32;

        self.logger.as_ref().map(|log| {
            debug!(log, "report";
                "sid" => sock_id,
                "rtt(us)" => rtt,
                "rin(Bps)" => rin,
                "rout(Bps)" => rout,
                "loss(pkts)" => loss,
            );
        });

        let update = match self.const_param {
            Constant::Cwnd(c) => vec![("Cwnd", c * self.mss)],
            Constant::Rate {
                rate: r,
                cwnd_cap: c,
            } => vec![("Cwnd", c * self.mss), ("Rate", r)],
        };
        if let Err(e) = self.control_channel.update_field(&self.sc, &update) {
            self.logger.as_ref().map(|log| {
                warn!(log, "rate update error"; "err" => ?e,);
            });
        }
    }
}
