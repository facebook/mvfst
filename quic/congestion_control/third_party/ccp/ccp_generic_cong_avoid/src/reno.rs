extern crate portus_export;
extern crate slog;

pub use crate::GenericCongAvoidAlg;
pub use crate::GenericCongAvoidFlow;
pub use crate::GenericCongAvoidMeasurements;

#[derive(Default)]
pub struct Reno {
    mss: u32,
    init_cwnd: f64,
    cwnd: f64,
}

impl GenericCongAvoidAlg for Reno {
    type Flow = Self;

    fn name() -> &'static str {
        "reno"
    }

    fn with_args(_: &clap::ArgMatches) -> Self {
        Default::default()
    }

    fn new_flow(&self, _logger: Option<slog::Logger>, init_cwnd: u32, mss: u32) -> Self::Flow {
        Reno {
            mss,
            init_cwnd: f64::from(init_cwnd),
            cwnd: f64::from(init_cwnd),
        }
    }
}

impl GenericCongAvoidFlow for Reno {
    fn curr_cwnd(&self) -> u32 {
        self.cwnd as u32
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = f64::from(cwnd);
    }

    fn increase(&mut self, m: &GenericCongAvoidMeasurements) {
        // increase cwnd by 1 / cwnd per packet
        self.cwnd += 3.0 * f64::from(self.mss) * (f64::from(m.acked) / self.cwnd);
    }

    fn reduction(&mut self, _m: &GenericCongAvoidMeasurements) {
        self.cwnd /= 2.0;
        if self.cwnd <= self.init_cwnd {
            self.cwnd = self.init_cwnd;
        }
    }
}
