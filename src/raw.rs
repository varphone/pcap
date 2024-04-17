// GRCOV_EXCL_START
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use libc::{
    c_char, c_int, c_uchar, c_uint, c_ushort, c_void, intptr_t, size_t, sockaddr, timeval, FILE,
};

// #[cfg(test)]
// use mockall::automock;

pub const PCAP_IF_LOOPBACK: u32 = 0x00000001;
pub const PCAP_IF_UP: u32 = 0x00000002;
pub const PCAP_IF_RUNNING: u32 = 0x00000004;
pub const PCAP_IF_WIRELESS: u32 = 0x00000008;
pub const PCAP_IF_CONNECTION_STATUS: u32 = 0x00000030;
pub const PCAP_IF_CONNECTION_STATUS_UNKNOWN: u32 = 0x00000000;
pub const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x00000010;
pub const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x00000020;
pub const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: u32 = 0x00000030;

pub type bpf_u_int32 = c_uint;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
}

pub enum pcap_t {}

pub enum pcap_dumper_t {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_file_header {
    pub magic: c_uint,
    pub version_major: c_ushort,
    pub version_minor: c_ushort,
    pub thiszone: c_int,
    pub sigfigs: c_uint,
    pub snaplen: c_uint,
    pub linktype: c_uint,
}

pub type pcap_direction_t = c_uint;

pub const PCAP_D_INOUT: pcap_direction_t = 0;
pub const PCAP_D_IN: pcap_direction_t = 1;
pub const PCAP_D_OUT: pcap_direction_t = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_stat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_if_t {
    pub next: *mut pcap_if_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr_t,
    pub flags: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_addr_t {
    pub next: *mut pcap_addr_t,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_send_queue {
    pub maxlen: c_uint,
    pub len: c_uint,
    pub buffer: *mut c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_rmtauth {
    pub r#type: c_int,
    pub username: *mut c_char,
    pub password: *mut c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_samp {
    pub method: c_int,
    pub value: c_int,
}

// This is not Option<fn>, pcap functions do not check if the handler is null so it is wrong to
// pass them Option::<fn>::None.
pub type pcap_handler =
    extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) -> ();

// #[cfg_attr(test, automock)]
pub mod ffi {
    use crate::api::Api;

    use super::*;

    // [OBSOLETE] pub unsafe fn pcap_lookupdev(arg1: *mut c_char) -> *mut c_char;
    // pub unsafe fn pcap_lookupnet(arg1: *const c_char, arg2: *mut c_uint, arg3: *mut c_uint,
    //                       arg4: *mut c_char) -> c_int;
    pub unsafe fn pcap_create(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        Api::get().create(arg1, arg2)
    }

    pub unsafe fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_snaplen(arg1, arg2)
    }

    pub unsafe fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_promisc(arg1, arg2)
    }

    // pub unsafe fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
    pub unsafe fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_timeout(arg1, arg2)
    }

    pub unsafe fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_buffer_size(arg1, arg2)
    }

    pub unsafe fn pcap_activate(arg1: *mut pcap_t) -> c_int {
        Api::get().activate(arg1)
    }

    pub unsafe fn pcap_open_live(
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut c_char,
    ) -> *mut pcap_t {
        Api::get().open_live(arg1, arg2, arg3, arg4, arg5)
    }

    pub unsafe fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t {
        Api::get().open_dead(arg1, arg2)
    }

    pub unsafe fn pcap_open_offline(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        Api::get().open_offline(arg1, arg2)
    }

    #[cfg(not(windows))]
    pub unsafe fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t {
        Api::get().fopen_offline(arg1, arg2)
    }

    #[cfg(all(windows, target_env = "msvc"))]
    #[link(name = "msvcrt")]
    extern "C" {
        fn _get_osfhandle(fd: c_int) -> intptr_t;
    }

    #[cfg(all(windows, target_env = "msvc"))]
    pub unsafe fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t {
        Api::get().hopen_offline(_get_osfhandle(libc::fileno(arg1)), arg2)
    }

    pub unsafe fn pcap_close(arg1: *mut pcap_t) {
        Api::get().close(arg1)
    }

    pub unsafe fn pcap_loop(
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int {
        Api::get().r#loop(arg1, arg2, arg3, arg4)
    }

    // pub unsafe fn pcap_dispatch(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
    //                      arg4: *mut c_uchar)-> c_int;
    // pub unsafe fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;

    pub unsafe fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int {
        Api::get().next_ex(arg1, arg2, arg3)
    }

    pub unsafe fn pcap_breakloop(arg1: *mut pcap_t) {
        Api::get().breakloop(arg1)
    }

    pub unsafe fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int {
        Api::get().stats(arg1, arg2)
    }

    pub unsafe fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int {
        Api::get().setfilter(arg1, arg2)
    }

    pub unsafe fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int {
        Api::get().setdirection(arg1, arg2)
    }

    // pub unsafe fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;

    pub unsafe fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int {
        Api::get().setnonblock(arg1, arg2, arg3)
    }

    pub unsafe fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int {
        Api::get().sendpacket(arg1, arg2, arg3)
    }

    // pub unsafe fn pcap_statustostr(arg1: c_int) -> *const c_char;

    // pub unsafe fn pcap_strerror(arg1: c_int) -> *const c_char;

    pub unsafe fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char {
        Api::get().geterr(arg1)
    }

    // pub unsafe fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_char);

    pub unsafe fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int {
        Api::get().compile(arg1, arg2, arg3, arg4, arg5)
    }

    // pub unsafe fn pcap_compile_nopcap(arg1: c_int, arg2: c_int, arg3: *mut bpf_program,
    //                            arg4: *const c_char, arg5: c_int, arg6: c_uint) -> c_int;

    pub unsafe fn pcap_freecode(arg1: *mut bpf_program) {
        Api::get().freecode(arg1)
    }

    pub unsafe fn pcap_offline_filter(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int {
        Api::get().offline_filter(arg1, arg2, arg3)
    }

    pub unsafe fn pcap_datalink(arg1: *mut pcap_t) -> c_int {
        Api::get().datalink(arg1)
    }

    // pub unsafe fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;

    pub unsafe fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
        Api::get().list_datalinks(arg1, arg2)
    }

    pub unsafe fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_datalink(arg1, arg2)
    }

    pub unsafe fn pcap_free_datalinks(arg1: *mut c_int) {
        Api::get().free_datalinks(arg1)
    }

    pub unsafe fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int {
        Api::get().datalink_name_to_val(arg1)
    }

    pub unsafe fn pcap_datalink_val_to_name(arg1: c_int) -> *const c_char {
        Api::get().datalink_val_to_name(arg1)
    }

    pub unsafe fn pcap_datalink_val_to_description(arg1: c_int) -> *const c_char {
        Api::get().datalink_val_to_description(arg1)
    }

    // pub unsafe fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;

    // pub unsafe fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;

    pub unsafe fn pcap_major_version(arg1: *mut pcap_t) -> c_int {
        Api::get().major_version(arg1)
    }

    pub unsafe fn pcap_minor_version(arg1: *mut pcap_t) -> c_int {
        Api::get().minor_version(arg1)
    }

    // pub unsafe fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;

    pub unsafe fn pcap_fileno(arg1: *mut pcap_t) -> c_int {
        Api::get().fileno(arg1)
    }

    pub unsafe fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t {
        Api::get().dump_open(arg1, arg2)
    }

    #[cfg(not(windows))]
    pub unsafe fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t {
        Api::get().dump_fopen(arg1, fp)
    }

    #[cfg(all(windows, target_env = "msvc"))]
    pub unsafe fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t {
        Api::get().dump_hopen(arg1, _get_osfhandle(libc::fileno(fp)))
    }

    // pub unsafe fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
    
    // pub unsafe fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;

    pub unsafe fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int {
        Api::get().dump_flush(arg1)
    }

    pub unsafe fn pcap_dump_close(arg1: *mut pcap_dumper_t) {
        Api::get().dump_close(arg1)
    }

    pub unsafe fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) {
        Api::get().dump(arg1, arg2, arg3)
    }

    pub unsafe fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int {
        Api::get().findalldevs(arg1, arg2)
    }

    pub unsafe fn pcap_freealldevs(arg1: *mut pcap_if_t) {
        Api::get().freealldevs(arg1)
    }

    pub unsafe fn pcap_lib_version() -> *const c_char {
        Api::get().lib_version()
    }

    pub unsafe fn bpf_image(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char {
        Api::get().bpf_image(arg1, arg2)
    }

    pub unsafe fn bpf_dump(arg1: *const bpf_program, arg2: c_int) {
        Api::get().bpf_dump(arg1, arg2)
    }

    #[cfg(not(windows))]
    pub unsafe fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int {
        Api::get().get_selectable_fd(arg1)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_free_tstamp_types(arg1: *mut c_int) {
        Api::get().free_tstamp_types(arg1)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
        Api::get().list_tstamp_types(arg1, arg2)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_tstamp_type_name_to_val(arg1: *const c_char) -> c_int {
        Api::get().tstamp_type_name_to_val(arg1)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_tstamp_type_val_to_description(arg1: c_int) -> *const c_char {
        Api::get().tstamp_type_val_to_description(arg1)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_tstamp_type_val_to_name(arg1: c_int) -> *const c_char {
        Api::get().tstamp_type_val_to_name(arg1)
    }

    #[cfg(libpcap_1_2)]
    pub unsafe fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_tstamp_type(arg1, arg2)
    }

    #[cfg(all(not(windows), libpcap_1_5))]
    pub unsafe fn pcap_fopen_offline_with_tstamp_precision(
        arg1: *mut FILE,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t {
        Api::get().fopen_offline_with_tstamp_precision(arg1, arg2, arg3)
    }

    #[cfg(libpcap_1_5)]
    pub unsafe fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> c_int {
        Api::get().get_tstamp_precision(arg1)
    }

    #[cfg(libpcap_1_5)]
    pub unsafe fn pcap_open_dead_with_tstamp_precision(
        arg1: c_int,
        arg2: c_int,
        arg3: c_uint,
    ) -> *mut pcap_t {
        Api::get().open_dead_with_tstamp_precision(arg1, arg2, arg3)
    }

    #[cfg(libpcap_1_5)]
    pub unsafe fn pcap_open_offline_with_tstamp_precision(
        arg1: *const c_char,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t {
        Api::get().open_offline_with_tstamp_precision(arg1, arg2, arg3)
    }

    #[cfg(libpcap_1_5)]
    pub unsafe fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_immediate_mode(arg1, arg2)
    }

    #[cfg(libpcap_1_5)]
    pub unsafe fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_tstamp_precision(arg1, arg2)
    }

    #[cfg(libpcap_1_7)]
    pub unsafe fn pcap_dump_open_append(
        arg1: *mut pcap_t,
        arg2: *const c_char,
    ) -> *mut pcap_dumper_t {
        Api::get().dump_open_append(arg1, arg2)
    }

    #[cfg(libpcap_1_8)]
    pub unsafe fn pcap_oid_get_request(
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *mut c_void,
        arg4: *mut size_t,
    ) -> c_int {
        Api::get().oid_get_request(arg1, arg2, arg3, arg4)
    }

    #[cfg(libpcap_1_8)]
    pub unsafe fn pcap_oid_set_request(
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *const c_void,
        arg4: *mut size_t,
    ) -> c_int {
        Api::get().oid_set_request(arg1, arg2, arg3, arg4)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_bufsize(arg1: *mut pcap_t) -> c_int {
        Api::get().bufsize(arg1)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_createsrcstr(
        arg1: *mut c_char,
        arg2: c_int,
        arg3: *const c_char,
        arg4: *const c_char,
        arg5: *const c_char,
        arg6: *mut c_char,
    ) -> c_int {
        Api::get().createsrcstr(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_dump_ftell64(arg1: *mut pcap_dumper_t) -> i64 {
        Api::get().dump_ftell64(arg1)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_findalldevs_ex(
        arg1: *const c_char,
        arg2: *mut pcap_rmtauth,
        arg3: *mut *mut pcap_if_t,
        arg4: *mut c_char,
    ) -> c_int {
        Api::get().findalldevs_ex(arg1, arg2, arg3, arg4)
    }

    #[cfg(all(libpcap_1_9, not(windows)))]
    pub unsafe fn pcap_get_required_select_timeout(arg1: *mut pcap_t, arg2: *mut timeval) -> c_int {
        Api::get().get_required_select_timeout(arg1, arg2)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_open(
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> *mut pcap_t {
        Api::get().open(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_parsesrcstr(
        arg1: *const c_char,
        arg2: *mut c_int,
        arg3: *mut c_char,
        arg4: *mut c_char,
        arg5: *mut c_char,
        arg6: *mut c_char,
    ) -> c_int {
        Api::get().parsesrcstr(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_remoteact_accept(
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> c_int {
        Api::get().remoteact_accept(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_remoteact_cleanup() {
        Api::get().remoteact_cleanup()
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_remoteact_close(arg1: *const c_char, arg2: *mut c_char) -> c_int {
        Api::get().remoteact_close(arg1, arg2)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_remoteact_list(
        arg1: *mut c_char,
        arg2: c_char,
        arg3: c_int,
        arg4: *mut c_char,
    ) -> c_int {
        Api::get().remoteact_list(arg1, arg2, arg3, arg4)
    }

    #[cfg(all(libpcap_1_9, not(windows)))]
    pub unsafe fn pcap_set_protocol_linux(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().set_protocol_linux(arg1, arg2)
    }

    #[cfg(libpcap_1_9)]
    pub unsafe fn pcap_setsampling(arg1: *mut pcap_t) -> *mut pcap_samp {
        Api::get().setsampling(arg1)
    }

    #[cfg(libpcap_1_10)]
    pub unsafe fn pcap_remoteact_accept_ex(
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: c_int,
        arg7: *mut c_char,
    ) -> c_int {
        Api::get().remoteact_accept_ex(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
    }

    #[cfg(libpcap_1_10)]
    pub unsafe fn pcap_datalink_val_to_description_or_dlt(arg1: c_int) -> *const c_char {
        Api::get().datalink_val_to_description_or_dlt(arg1)
    }
}

#[cfg(not(windows))]
// #[cfg_attr(test, automock)]
pub mod ffi_unix {
    use super::*;

    #[link(name = "pcap")]
    extern "C" {
        // pub unsafe fn pcap_inject(arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int;
        pub unsafe fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: c_int) -> c_int {
            0
        }
    }
}

#[cfg(windows)]
// #[cfg_attr(test, automock)]
pub mod ffi_windows {
    use super::*;
    use crate::api::Api;
    use windows_sys::Win32::Foundation::HANDLE;

    pub const WINPCAP_MINTOCOPY_DEFAULT: c_int = 16000;

    pub unsafe fn pcap_setbuff(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().setbuff(arg1, arg2)
    }

    pub unsafe fn pcap_setmode(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().setmode(arg1, arg2)
    }

    pub unsafe fn pcap_setmintocopy(arg1: *mut pcap_t, arg2: c_int) -> c_int {
        Api::get().setmintocopy(arg1, arg2)
    }

    pub unsafe fn pcap_getevent(p: *mut pcap_t) -> HANDLE {
        Api::get().getevent(p)
    }

    pub unsafe fn pcap_sendqueue_alloc(memsize: c_uint) -> *mut pcap_send_queue {
        Api::get().sendqueue_alloc(memsize)
    }

    pub unsafe fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue) {
        Api::get().sendqueue_destroy(queue)
    }

    pub unsafe fn pcap_sendqueue_queue(
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> c_int {
        Api::get().sendqueue_queue(queue, pkt_header, pkt_data)
    }

    pub unsafe fn pcap_sendqueue_transmit(
        p: *mut pcap_t,
        queue: *mut pcap_send_queue,
        sync: c_int,
    ) -> c_uint {
        Api::get().sendqueue_transmit(p, queue, sync)
    }
}

// The conventional solution is to use `mockall_double`. However, automock's requirement for an
// inner module would require changing the imports in all the files using this module. This approach
// allows all the other modules to keep using the `raw` module as before.
// #[cfg(not(test))]
pub use ffi::*;

// #[cfg(not(test))]
#[cfg(not(windows))]
pub use ffi_unix::*;

// #[cfg(not(test))]
#[cfg(windows)]
pub use ffi_windows::*;

// #[cfg(test)]
// pub use mock_ffi::*;

// #[cfg(test)]
// #[cfg(not(windows))]
// pub use mock_ffi_unix::*;

// #[cfg(test)]
// #[cfg(windows)]
// pub use mock_ffi_windows::*;

#[cfg(test)]
pub mod testmod {
    use std::{ffi::CString, sync::Mutex};

    use once_cell::sync::Lazy;

    use super::*;

    pub struct GeterrContext(__pcap_geterr::Context);

    // Must be acquired by any test using mock FFI.
    pub static RAWMTX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    pub fn as_pcap_t<T: ?Sized>(value: &mut T) -> *mut pcap_t {
        value as *mut T as *mut pcap_t
    }

    pub fn as_pcap_dumper_t<T: ?Sized>(value: &mut T) -> *mut pcap_dumper_t {
        value as *mut T as *mut pcap_dumper_t
    }

    pub fn geterr_expect(pcap: *mut pcap_t) -> GeterrContext {
        // Lock must be acquired by caller.
        assert!(RAWMTX.try_lock().is_err());

        let err = CString::new("oh oh").unwrap();
        let ctx = pcap_geterr_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once_st(|_| err.into_raw());

        GeterrContext(ctx)
    }
}
// GRCOV_EXCL_STOP
