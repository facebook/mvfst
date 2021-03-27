extern crate portus_export;
extern crate slog;
extern crate time;

pub use crate::GenericCongAvoidAlg;
pub use crate::GenericCongAvoidFlow;
pub use crate::GenericCongAvoidMeasurements;

#[derive(Default)]
pub struct Cubic {
    pkt_size: u32,
    init_cwnd: u32,

    cwnd: f64,
    cwnd_cnt: f64,
    tcp_friendliness: bool,
    beta: f64,
    fast_convergence: bool,
    c: f64,
    wlast_max: f64,
    epoch_start: f64,
    origin_point: f64,
    d_min: f64,
    wtcp: f64,
    k: f64,
    ack_cnt: f64,
    cnt: f64,
    cubic_rtt: f64,
}

impl Cubic {
    fn cubic_update(&mut self) {
        self.ack_cnt += 1.0;
        if self.epoch_start <= 0.0 {
            self.epoch_start =
                (time::get_time().sec as f64) + f64::from(time::get_time().nsec) / 1_000_000_000.0;
            if self.cwnd < self.wlast_max {
                let temp = (self.wlast_max - self.cwnd) / self.c;
                self.k = (temp.max(0.0)).powf(1.0 / 3.0);
                self.origin_point = self.wlast_max;
            } else {
                self.k = 0.0;
                self.origin_point = self.cwnd;
            }

            self.ack_cnt = 1.0;
            self.wtcp = self.cwnd
        }

        let t = (time::get_time().sec as f64)
            + f64::from(time::get_time().nsec) / 1_000_000_000.0
            + self.d_min
            - self.epoch_start;
        let target = self.origin_point + self.c * ((t - self.k) * (t - self.k) * (t - self.k));
        if target > self.cwnd {
            self.cnt = self.cwnd / (target - self.cwnd);
        } else {
            self.cnt = 100.0 * self.cwnd;
        }

        if self.tcp_friendliness {
            self.cubic_tcp_friendliness();
        }
    }

    fn cubic_tcp_friendliness(&mut self) {
        self.wtcp += ((3.0 * self.beta) / (2.0 - self.beta)) * (self.ack_cnt / self.cwnd);
        self.ack_cnt = 0.0;
        if self.wtcp > self.cwnd {
            let max_cnt = self.cwnd / (self.wtcp - self.cwnd);
            if self.cnt > max_cnt {
                self.cnt = max_cnt;
            }
        }
    }

    fn cubic_reset(&mut self) {
        self.wlast_max = 0.0;
        self.epoch_start = -0.1;
        self.origin_point = 0.0;
        self.d_min = -0.1;
        self.wtcp = 0.0;
        self.k = 0.0;
        self.ack_cnt = 0.0;
    }
}

impl GenericCongAvoidAlg for Cubic {
    type Flow = Self;

    fn name() -> &'static str {
        "cubic"
    }

    fn with_args(_: &clap::ArgMatches) -> Self {
        Default::default()
    }

    fn new_flow(&self, _logger: Option<slog::Logger>, init_cwnd: u32, mss: u32) -> Self::Flow {
        Cubic {
            pkt_size: mss,
            init_cwnd: init_cwnd / mss,
            cwnd: f64::from(init_cwnd / mss),
            cwnd_cnt: 0.0f64,
            tcp_friendliness: true,
            beta: 0.3f64,
            fast_convergence: true,
            c: 0.4f64,
            wlast_max: 0.0f64,
            epoch_start: -0.1f64,
            origin_point: 0.0f64,
            d_min: -0.1f64,
            wtcp: 0.0f64,
            k: 0.0f64,
            ack_cnt: 0.0f64,
            cnt: 0.0f64,
            cubic_rtt: 0.1f64,
        }
    }
}

impl GenericCongAvoidFlow for Cubic {
    fn curr_cwnd(&self) -> u32 {
        (self.cwnd * f64::from(self.pkt_size)) as u32
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = f64::from(cwnd) / f64::from(self.pkt_size);
    }

    fn increase(&mut self, m: &GenericCongAvoidMeasurements) {
        self.cubic_rtt = (f64::from(m.rtt)) * 0.000_001;
        let f_rtt = (f64::from(m.rtt)) * 0.000_001;
        let no_of_acks = ((f64::from(m.acked)) / (f64::from(self.pkt_size))) as u32;
        for _i in 0..no_of_acks {
            if self.d_min <= 0.0 || f_rtt < self.d_min {
                self.d_min = f_rtt;
            }

            self.cubic_update();
            if self.cwnd_cnt > self.cnt {
                self.cwnd += 1.0;
                self.cwnd_cnt = 0.0;
            } else {
                self.cwnd_cnt += 1.0;
            }
        }
    }

    fn reduction(&mut self, _m: &GenericCongAvoidMeasurements) {
        self.epoch_start = -0.1;
        if self.cwnd < self.wlast_max && self.fast_convergence {
            self.wlast_max = self.cwnd * ((2.0 - self.beta) / 2.0);
        } else {
            self.wlast_max = self.cwnd;
        }

        self.cwnd *= 1.0 - self.beta;
        if self.cwnd as u32 <= self.init_cwnd {
            self.cwnd = f64::from(self.init_cwnd);
        }
    }

    fn reset(&mut self) {
        self.cubic_reset();
    }
}
