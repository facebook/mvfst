extern crate clap;
extern crate time;

#[macro_use]
extern crate slog;

extern crate generic_cong_avoid;
extern crate portus;

use generic_cong_avoid::reno::Reno;

fn main() {
    let log = portus::algs::make_logger();
    let (alg, ipc) = generic_cong_avoid::make_args("CCP Reno", log.clone())
        .map_err(|e| warn!(log, "bad argument"; "err" => ?e))
        .unwrap();

    info!(log, "initializing";
        "reports" => ?alg.report_option,
        "slow_start_mode" => ?alg.ss,
    );

    generic_cong_avoid::start::<Reno>(ipc.as_str(), log, alg);
}
