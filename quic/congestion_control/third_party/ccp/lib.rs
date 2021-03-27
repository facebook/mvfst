#![feature(atomic_mut_ptr)]
// Step 1/2: Add new alg crates here.
//
// NOTE: Must be listed in TARGETS deps
extern crate ccp_const;
extern crate ccp_generic_cong_avoid;

extern crate clap;
extern crate portus;

use libc::c_char;
use portus::ipc::unix::Socket as S;
use portus::ipc::Blocking as B;
use portus::{CongAlg, CongAlgBuilder};
use std::sync::{atomic, Arc};
use std::ffi::CStr;
use std::fs::File;
use std::os::unix::io::FromRawFd;

use ccp_generic_cong_avoid::{cubic::Cubic, reno::Reno};

fn _start(args: String, out: Option<File>, uid: u64, handle: *const atomic::AtomicBool) {
    // Parse config arguments
    let argv = args.split_whitespace();
    let alg_name = argv.clone().next().expect("empty argument string");
    let log = out.map_or_else(
        || portus::algs::make_logger(),
        |f| portus::algs::make_file_logger(f),
    );

    let portus_bindaddr = format!("{}/{}", uid.to_string(), "portus");
    let backend = S::<B>::new(&portus_bindaddr)
        .map(|sk| portus::ipc::BackendBuilder { sock : sk })
        .expect("ipc initialization");

    let mut available_algs = vec![];

    macro_rules! register_alg {
        ($alg:ident) => {
            let reg_name = <$alg::__ccp_alg_export as CongAlg<S<B>>>::name();
            available_algs.push(reg_name);
            if alg_name == reg_name {
                let args = $alg::__ccp_alg_export::args();
                let matches = args.get_matches_from(argv);
                let alg =
                    $alg::__ccp_alg_export::with_arg_matches(&matches, Some(log.clone())).unwrap();
                portus::run_with_handle::<_, _>(backend, portus::Config { logger : Some(log) }, alg, handle).unwrap();
                return;
            }
        };
        ($pkg:ident, $base:ident, $alg:ident) => {
            let reg_name = <$pkg::$base<$alg> as CongAlg<S<B>>>::name();
            available_algs.push(reg_name);
            if alg_name == reg_name {
                let args = <$pkg::$base<$alg> as CongAlgBuilder<'_, '_>>::args();
                let matches = args.get_matches_from(argv);
                let alg = <$pkg::$base<$alg> as CongAlgBuilder<'_, '_>>::with_arg_matches(
                    &matches,
                    Some(log.clone()),
                )
                .unwrap();
                portus::run_with_handle::<_, _>(backend, portus::Config { logger : Some(log) }, alg, handle).unwrap();
                return;
            }
        };
    }

    register_alg!(ccp_const);
    register_alg!(ccp_generic_cong_avoid, Alg, Reno);
    register_alg!(ccp_generic_cong_avoid, Alg, Cubic);

    unreachable!("error: algorithm '{}' not found! available algorithms: {:#?}", alg_name, available_algs);
}

#[no_mangle]
pub extern "C" fn ccp_create_handle() -> *const atomic::AtomicBool {
    let handle = Arc::new(atomic::AtomicBool::new(true));
    println!("{:#?}", handle);

    return Arc::into_raw(handle)
}

#[no_mangle]
pub extern "C" fn ccp_spawn(c_args: *const c_char, log_fd: i32, uid: u64, handle: *const atomic::AtomicBool) {
    let args = unsafe { CStr::from_ptr(c_args) }
        .to_string_lossy()
        .into_owned();
    let f = unsafe { File::from_raw_fd(log_fd) };
    _start(args, Some(f), uid, handle)
}

#[no_mangle]
pub extern "C" fn ccp_kill(handle: *const atomic::AtomicBool) {
    let a = unsafe { Arc::from_raw(handle) };
    a.store(false, std::sync::atomic::Ordering::SeqCst);
    // forget so we don't drop it automatically at the end, calling code has ownership
    let _ = Arc::into_raw(a);
}
