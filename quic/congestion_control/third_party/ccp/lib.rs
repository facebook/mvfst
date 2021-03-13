// Step 1/2: Add new alg crates here.
//
// NOTE: Must be listed in TARGETS deps

extern crate clap;
extern crate portus;

use libc::c_char;
use portus::ipc::unix::Socket as S;
use portus::ipc::Blocking as B;
use portus::{CongAlg, CongAlgBuilder};
use std::ffi::CStr;
use std::fs::File;
use std::os::unix::io::FromRawFd;

fn _start(args: String, ipc: String, out: Option<File>) -> u32 {
    // Parse config arguments
    let argv = args.split_whitespace();
    let alg_name = argv.clone().next().expect("empty argument string");
    let log = out.map_or_else(
        || portus::algs::make_logger(),
        |f| portus::algs::make_file_logger(f),
    );

    macro_rules! register_alg {
        ($alg:ident) => {
            if alg_name == <$alg::__ccp_alg_export as CongAlg<S<B>>>::name() {
                let args = $alg::__ccp_alg_export::args();
                let matches = args.get_matches_from(argv.clone());
                let alg =
                    $alg::__ccp_alg_export::with_arg_matches(&matches, Some(log.clone())).unwrap();
                portus::start!(&ipc[..], Some(log.clone()), alg).expect("portus crashed")
            }
        };
        ($pkg:ident, $base:ident, $alg:ident) => {
            if alg_name == <$pkg::$base<$alg> as CongAlg<S<B>>>::name() {
                let args = <$pkg::$base<$alg> as CongAlgBuilder<'_, '_>>::args();
                let matches = args.get_matches_from(argv.clone());
                let alg = <$pkg::$base<$alg> as CongAlgBuilder<'_, '_>>::with_arg_matches(
                    &matches,
                    Some(log.clone()),
                )
                .unwrap();
                portus::start!(&ipc[..], Some(log.clone()), alg).expect("portus crashed")
            }
        };
    }

    eprintln!("error: algorithm '{}' not found!", alg_name);
    1
}

#[no_mangle]
pub extern "C" fn ccp_run_forever(c_args: *const c_char, log_fd: i32) -> u32 {
    let args = unsafe { CStr::from_ptr(c_args) }
        .to_string_lossy()
        .into_owned();
    let f = unsafe { File::from_raw_fd(log_fd) };
    _start(args, String::from("unix"), Some(f))
}
