#[cfg(windows)]
use crate::raw::PAirpcapHandle;
use crate::raw::{
    bpf_insn, bpf_program, bpf_u_int32, pcap_direction_t, pcap_dumper_t, pcap_handler, pcap_if_t,
    pcap_pkthdr, pcap_send_queue, pcap_stat, pcap_t,
};
#[cfg(libpcap_1_9)]
use crate::raw::{pcap_rmtauth, pcap_samp};
#[cfg(not(windows))]
use libc::timeval;
use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_void, intptr_t, size_t, FILE};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

pub mod ffi {
    use super::*;

    pub type PcapLookupnet = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: *mut bpf_u_int32,
        arg3: *mut bpf_u_int32,
        arg4: *mut c_char,
    ) -> c_int;
    pub type PcapCreate =
        unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub type PcapSetSnaplen = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetPromisc = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapCanSetRfmon = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapSetRfmon = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetTimeout = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetBufferSize = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapActivate = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapOpenLive = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut c_char,
    ) -> *mut pcap_t;
    pub type PcapOpenDead = unsafe extern "C" fn(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub type PcapOpenOffline =
        unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    #[cfg(not(windows))]
    pub type PcapFopenOffline =
        unsafe extern "C" fn(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
    pub type PcapClose = unsafe extern "C" fn(arg1: *mut pcap_t);
    pub type PcapLoop = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int;
    pub type PcapDispatch = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int;
    pub type PcapNext =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;
    pub type PcapNextEx = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int;
    pub type PcapBreakloop = unsafe extern "C" fn(arg1: *mut pcap_t);
    pub type PcapStats = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int;
    pub type PcapSetfilter =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
    pub type PcapSetdirection =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int;
    pub type PcapGetnonblock = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;
    pub type PcapSetnonblock =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
    pub type PcapInject =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int;
    pub type PcapSendpacket =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
    pub type PcapStatustostr = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapStrerror = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapGeterr = unsafe extern "C" fn(arg1: *mut pcap_t) -> *mut c_char;
    pub type PcapPerror = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char);
    pub type PcapCompile = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int;
    pub type PcapFreecode = unsafe extern "C" fn(arg1: *mut bpf_program);
    pub type PcapOfflineFilter = unsafe extern "C" fn(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int;
    pub type PcapDatalink = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapDatalinkExt = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapListDatalinks =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    pub type PcapSetDatalink = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapFreeDatalinks = unsafe extern "C" fn(arg1: *mut c_int);
    pub type PcapDatalinkNameToVal = unsafe extern "C" fn(arg1: *const c_char) -> c_int;
    pub type PcapDatalinkValToName = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapDatalinkValToDescription = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapSnapshot = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapIsSwapped = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapMajorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapMinorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapFile = unsafe extern "C" fn(arg1: *mut pcap_t) -> *mut FILE;
    pub type PcapFileno = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapDumpOpen =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
    #[cfg(not(windows))]
    pub type PcapDumpFopen =
        unsafe extern "C" fn(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
    pub type PcapDumpFile = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> *mut FILE;
    pub type PcapDumpFtell = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> c_long;
    pub type PcapDumpFlush = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> c_int;
    pub type PcapDumpClose = unsafe extern "C" fn(arg1: *mut pcap_dumper_t);
    pub type PcapDump =
        unsafe extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
    pub type PcapFindalldevs =
        unsafe extern "C" fn(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
    pub type PcapFreealldevs = unsafe extern "C" fn(arg1: *mut pcap_if_t);
    pub type PcapLibVersion = unsafe extern "C" fn() -> *const c_char;
    pub type BpfImage = unsafe extern "C" fn(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char;
    pub type BpfDump = unsafe extern "C" fn(arg1: *const bpf_program, arg2: c_int);
    #[cfg(not(windows))]
    pub type PcapGetSelectableFd = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;

    #[cfg(libpcap_1_2)]
    pub type PcapFreeTstampTypes = unsafe extern "C" fn(arg1: *mut c_int);

    #[cfg(libpcap_1_2)]
    pub type PcapListTstampTypes =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;

    #[cfg(libpcap_1_2)]
    pub type PcapTstampTypeNameToVal = unsafe extern "C" fn(arg1: *const c_char) -> c_int;

    #[cfg(libpcap_1_2)]
    pub type PcapTstampTypeValToDescription = unsafe extern "C" fn(arg1: c_int) -> *const c_char;

    #[cfg(libpcap_1_2)]
    pub type PcapTstampTypeValToName = unsafe extern "C" fn(arg1: c_int) -> *const c_char;

    #[cfg(libpcap_1_2)]
    pub type PcapSetTstampType = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;

    #[cfg(libpcap_1_5)]
    pub type PcapGetTstampPrecision = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;

    #[cfg(libpcap_1_5)]
    pub type PcapOpenDeadWithTstampPrecision =
        unsafe extern "C" fn(arg1: c_int, arg2: c_int, arg3: c_uint) -> *mut pcap_t;

    #[cfg(libpcap_1_5)]
    pub type PcapOpenOfflineWithTstampPrecision =
        unsafe extern "C" fn(arg1: *const c_char, arg2: c_uint, arg3: *mut c_char) -> *mut pcap_t;

    #[cfg(all(not(windows), libpcap_1_5))]
    pub type PcapFopenOfflineWithTstampPrecision =
        unsafe extern "C" fn(arg1: *mut FILE, arg2: c_uint, arg3: *const c_char) -> *mut pcap_t;

    #[cfg(libpcap_1_5)]
    pub type PcapSetImmediateMode = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;

    #[cfg(libpcap_1_5)]
    pub type PcapSetTstampPrecision = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;

    #[cfg(libpcap_1_7)]
    pub type PcapDumpOpenAppend =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;

    #[cfg(libpcap_1_8)]
    pub type PcapOidGetRequest = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *mut c_void,
        arg4: *mut size_t,
    ) -> c_int;

    #[cfg(libpcap_1_8)]
    pub type PcapOidSetRequest = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *const c_void,
        arg4: *mut size_t,
    ) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapBufsize = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapCreatesrcstr = unsafe extern "C" fn(
        arg1: *mut c_char,
        arg2: c_int,
        arg3: *const c_char,
        arg4: *const c_char,
        arg5: *const c_char,
        arg6: *mut c_char,
    ) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapDumpFtell64 = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> i64;

    #[cfg(libpcap_1_9)]
    pub type PcapFindalldevsEx = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: *mut pcap_rmtauth,
        arg3: *mut *mut pcap_if_t,
        arg4: *mut c_char,
    ) -> c_int;

    #[cfg(all(libpcap_1_9, not(windows)))]
    pub type PcapGetRequiredSelectTimeout =
        unsafe extern "C" fn(arg1: *mut pcap_t) -> *const timeval;

    #[cfg(libpcap_1_9)]
    pub type PcapOpen = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> *mut pcap_t;

    #[cfg(libpcap_1_9)]
    pub type PcapParsesrcstr = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: *mut c_int,
        arg3: *mut c_char,
        arg4: *mut c_char,
        arg5: *mut c_char,
        arg6: *mut c_char,
    ) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapRemoteactAccept = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapRemoteactCleanup = unsafe extern "C" fn();

    #[cfg(libpcap_1_9)]
    pub type PcapRemoteactClose =
        unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapRemoteactList = unsafe extern "C" fn(
        arg1: *mut c_char,
        arg2: c_char,
        arg3: c_int,
        arg4: *mut c_char,
    ) -> c_int;

    #[cfg(all(unix, libpcap_1_9))]
    pub type PcapSetProtocolLinux = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;

    #[cfg(libpcap_1_9)]
    pub type PcapSetsampling = unsafe extern "C" fn(arg1: *mut pcap_t) -> *mut pcap_samp;

    #[cfg(libpcap_1_10)]
    pub type PcapInit = unsafe extern "C" fn(arg1: c_uint, arg2: *mut c_char) -> c_int;

    #[cfg(libpcap_1_10)]
    pub type PcapRemoteactAcceptEx = unsafe extern "C" fn(
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: c_int,
        arg7: *mut c_char,
    ) -> c_int;

    #[cfg(libpcap_1_10)]
    pub type PcapDatalinkValToDescriptionOrDlt = unsafe extern "C" fn(arg1: c_int) -> *const c_char;

    #[cfg(windows)]
    pub type PcapDumpHopen =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: intptr_t) -> *mut pcap_dumper_t;
    #[cfg(windows)]
    pub type PcapHopenOffline =
        unsafe extern "C" fn(arg1: intptr_t, arg2: *const c_char) -> *mut pcap_t;
    #[cfg(all(windows, libpcap_1_5))]
    pub type PcapHopenOfflineWithTstampPrecision =
        unsafe extern "C" fn(arg1: intptr_t, arg2: c_uint, arg3: *const c_char) -> *mut pcap_t;
    #[cfg(windows)]
    pub type PcapSetbuff = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapSetmode = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapSetmintocopy = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapGetEvent = unsafe extern "C" fn(p: *mut pcap_t) -> HANDLE;
    #[cfg(windows)]
    pub type PcapSendQueueAlloc = unsafe extern "C" fn(memsize: c_uint) -> *mut pcap_send_queue;
    #[cfg(windows)]
    pub type PcapSendQueueDestroy = unsafe extern "C" fn(queue: *mut pcap_send_queue);
    #[cfg(windows)]
    pub type PcapSendQueueQueue = unsafe extern "C" fn(
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> c_int;
    #[cfg(windows)]
    pub type PcapSendQueueTransmit =
        unsafe extern "C" fn(p: *mut pcap_t, queue: *mut pcap_send_queue, sync: c_int) -> c_uint;
    #[cfg(windows)]
    pub type PcapStatsEx =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut c_int) -> *mut pcap_stat;
    #[cfg(windows)]
    pub type PcapSetUserBuffer = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapLiveDump = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: *mut c_char,
        arg3: c_int,
        arg4: c_int,
    ) -> c_int;
    #[cfg(windows)]
    pub type PcapLiveDumpEnded = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapStartOem = unsafe extern "C" fn(arg1: *mut c_char, arg2: c_int) -> c_int;
    #[cfg(windows)]
    pub type PcapGetAirpcapHandle = unsafe extern "C" fn(arg1: *mut pcap_t) -> PAirpcapHandle;
}

pub struct Api {
    pub lookupnet: ffi::PcapLookupnet,
    pub create: ffi::PcapCreate,
    pub set_snaplen: ffi::PcapSetSnaplen,
    pub set_promisc: ffi::PcapSetPromisc,
    pub can_set_rfmon: Option<ffi::PcapCanSetRfmon>,
    pub set_rfmon: Option<ffi::PcapSetRfmon>,
    pub set_timeout: ffi::PcapSetTimeout,
    pub set_buffer_size: ffi::PcapSetBufferSize,
    pub activate: ffi::PcapActivate,
    pub open_live: ffi::PcapOpenLive,
    pub open_dead: ffi::PcapOpenDead,
    pub open_offline: ffi::PcapOpenOffline,
    #[cfg(not(windows))]
    pub fopen_offline: ffi::PcapFopenOffline,
    pub close: ffi::PcapClose,
    pub r#loop: ffi::PcapLoop,
    pub dispatch: ffi::PcapDispatch,
    pub next: ffi::PcapNext,
    pub next_ex: ffi::PcapNextEx,
    pub breakloop: ffi::PcapBreakloop,
    pub stats: ffi::PcapStats,
    pub setfilter: ffi::PcapSetfilter,
    pub setdirection: ffi::PcapSetdirection,
    pub getnonblock: ffi::PcapGetnonblock,
    pub setnonblock: ffi::PcapSetnonblock,
    pub inject: Option<ffi::PcapInject>,
    pub sendpacket: ffi::PcapSendpacket,
    pub statustostr: Option<ffi::PcapStatustostr>,
    pub strerror: ffi::PcapStrerror,
    pub geterr: ffi::PcapGeterr,
    pub perror: ffi::PcapPerror,
    pub compile: ffi::PcapCompile,
    pub freecode: ffi::PcapFreecode,
    pub offline_filter: ffi::PcapOfflineFilter,
    pub datalink: ffi::PcapDatalink,
    pub datalink_ext: Option<ffi::PcapDatalinkExt>,
    pub list_datalinks: ffi::PcapListDatalinks,
    pub set_datalink: ffi::PcapSetDatalink,
    pub free_datalinks: ffi::PcapFreeDatalinks,
    pub datalink_name_to_val: ffi::PcapDatalinkNameToVal,
    pub datalink_val_to_name: ffi::PcapDatalinkValToName,
    pub datalink_val_to_description: ffi::PcapDatalinkValToDescription,
    pub snapshot: ffi::PcapSnapshot,
    pub is_swapped: ffi::PcapIsSwapped,
    pub major_version: ffi::PcapMajorVersion,
    pub minor_version: ffi::PcapMinorVersion,
    pub file: ffi::PcapFile,
    pub fileno: ffi::PcapFileno,
    pub dump_open: ffi::PcapDumpOpen,
    #[cfg(not(windows))]
    pub dump_fopen: ffi::PcapDumpFopen,
    pub dump_file: ffi::PcapDumpFile,
    pub dump_ftell: ffi::PcapDumpFtell,
    pub dump_flush: ffi::PcapDumpFlush,
    pub dump_close: ffi::PcapDumpClose,
    pub dump: ffi::PcapDump,
    pub findalldevs: ffi::PcapFindalldevs,
    pub freealldevs: ffi::PcapFreealldevs,
    pub lib_version: ffi::PcapLibVersion,
    pub bpf_image: ffi::BpfImage,
    pub bpf_dump: ffi::BpfDump,
    #[cfg(not(windows))]
    pub get_selectable_fd: ffi::PcapGetSelectableFd,

    #[cfg(libpcap_1_2)]
    pub free_tstamp_types: ffi::PcapFreeTstampTypes,
    #[cfg(libpcap_1_2)]
    pub list_tstamp_types: ffi::PcapListTstampTypes,
    #[cfg(libpcap_1_2)]
    pub tstamp_type_name_to_val: ffi::PcapTstampTypeNameToVal,
    #[cfg(libpcap_1_2)]
    pub tstamp_type_val_to_description: ffi::PcapTstampTypeValToDescription,
    #[cfg(libpcap_1_2)]
    pub tstamp_type_val_to_name: ffi::PcapTstampTypeValToName,
    #[cfg(libpcap_1_2)]
    pub set_tstamp_type: ffi::PcapSetTstampType,

    #[cfg(libpcap_1_5)]
    pub get_tstamp_precision: ffi::PcapGetTstampPrecision,
    #[cfg(libpcap_1_5)]
    pub open_dead_with_tstamp_precision: ffi::PcapOpenDeadWithTstampPrecision,
    #[cfg(libpcap_1_5)]
    pub open_offline_with_tstamp_precision: ffi::PcapOpenOfflineWithTstampPrecision,
    #[cfg(all(not(windows), libpcap_1_5))]
    pub fopen_offline_with_tstamp_precision: ffi::PcapFopenOfflineWithTstampPrecision,
    #[cfg(libpcap_1_5)]
    pub set_immediate_mode: ffi::PcapSetImmediateMode,
    #[cfg(libpcap_1_5)]
    pub set_tstamp_precision: ffi::PcapSetTstampPrecision,

    #[cfg(libpcap_1_7)]
    pub dump_open_append: ffi::PcapDumpOpenAppend,

    #[cfg(libpcap_1_8)]
    pub oid_get_request: ffi::PcapOidGetRequest,
    #[cfg(libpcap_1_8)]
    pub oid_set_request: ffi::PcapOidSetRequest,

    #[cfg(libpcap_1_9)]
    pub bufsize: ffi::PcapBufsize,
    #[cfg(libpcap_1_9)]
    pub createsrcstr: ffi::PcapCreatesrcstr,
    #[cfg(libpcap_1_9)]
    pub dump_ftell64: ffi::PcapDumpFtell64,
    #[cfg(libpcap_1_9)]
    pub findalldevs_ex: ffi::PcapFindalldevsEx,
    #[cfg(all(libpcap_1_9, not(windows)))]
    pub get_required_select_timeout: ffi::PcapGetRequiredSelectTimeout,
    #[cfg(libpcap_1_9)]
    pub open: ffi::PcapOpen,
    #[cfg(libpcap_1_9)]
    pub parsesrcstr: ffi::PcapParsesrcstr,
    #[cfg(libpcap_1_9)]
    pub remoteact_accept: ffi::PcapRemoteactAccept,
    #[cfg(libpcap_1_9)]
    pub remoteact_cleanup: ffi::PcapRemoteactCleanup,
    #[cfg(libpcap_1_9)]
    pub remoteact_close: ffi::PcapRemoteactClose,
    #[cfg(libpcap_1_9)]
    pub remoteact_list: ffi::PcapRemoteactList,
    #[cfg(all(unix, libpcap_1_9))]
    pub set_protocol_linux: ffi::PcapSetProtocolLinux,
    #[cfg(libpcap_1_9)]
    pub setsampling: ffi::PcapSetsampling,

    #[cfg(libpcap_1_10)]
    pub init: ffi::PcapInit,
    #[cfg(libpcap_1_10)]
    pub remoteact_accept_ex: ffi::PcapRemoteactAcceptEx,
    #[cfg(libpcap_1_10)]
    pub datalink_val_to_description_or_dlt: ffi::PcapDatalinkValToDescriptionOrDlt,

    #[cfg(windows)]
    pub dump_hopen: Option<ffi::PcapDumpHopen>,
    #[cfg(windows)]
    pub hopen_offline: ffi::PcapHopenOffline,
    #[cfg(all(windows, libpcap_1_5))]
    pub hopen_offline_with_tstamp_precision: ffi::PcapHopenOfflineWithTstampPrecision,
    #[cfg(windows)]
    pub setbuff: ffi::PcapSetbuff,
    #[cfg(windows)]
    pub setmode: ffi::PcapSetmode,
    #[cfg(windows)]
    pub setmintocopy: ffi::PcapSetmintocopy,
    #[cfg(windows)]
    pub getevent: ffi::PcapGetEvent,
    #[cfg(windows)]
    pub sendqueue_alloc: ffi::PcapSendQueueAlloc,
    #[cfg(windows)]
    pub sendqueue_destroy: ffi::PcapSendQueueDestroy,
    #[cfg(windows)]
    pub sendqueue_queue: ffi::PcapSendQueueQueue,
    #[cfg(windows)]
    pub sendqueue_transmit: ffi::PcapSendQueueTransmit,
    #[cfg(windows)]
    pub stats_ex: ffi::PcapStatsEx,
    #[cfg(windows)]
    pub setuserbuffer: ffi::PcapSetUserBuffer,
    #[cfg(windows)]
    pub live_dump: ffi::PcapLiveDump,
    #[cfg(windows)]
    pub live_dump_ended: ffi::PcapLiveDumpEnded,
    #[cfg(windows)]
    pub start_oem: Option<ffi::PcapStartOem>,
    #[cfg(windows)]
    pub get_airpcap_handle: ffi::PcapGetAirpcapHandle,
    _lib: libloading::Library,
}

impl Api {
    pub fn new() -> Result<Self, libloading::Error> {
        #[cfg(all(unix, not(target_os = "macos")))]
        let libfile = "libpcap.so";
        #[cfg(target_os = "macos")]
        let libfile = "libpcap.dylib";
        #[cfg(windows)]
        let libfile = "wpcap.dll";
        unsafe {
            let lib = libloading::Library::new(libfile)?;
            Ok(Self {
                lookupnet: lib
                    .get(b"pcap_lookupnet")
                    .map(|f| *f)
                    .expect("pcap_lookupnet not loaded"),
                create: lib
                    .get(b"pcap_create")
                    .map(|f| *f)
                    .expect("pcap_create not loaded"),
                set_snaplen: lib
                    .get(b"pcap_set_snaplen")
                    .map(|f| *f)
                    .expect("pcap_set_snaplen not loaded"),
                set_promisc: lib
                    .get(b"pcap_set_promisc")
                    .map(|f| *f)
                    .expect("pcap_set_promisc not loaded"),
                can_set_rfmon: lib.get(b"pcap_can_set_rfmon").map(|f| *f).ok(),
                set_rfmon: lib.get(b"pcap_set_rfmon").map(|f| *f).ok(),
                set_timeout: lib
                    .get(b"pcap_set_timeout")
                    .map(|f| *f)
                    .expect("pcap_set_timeout not loaded"),
                set_buffer_size: lib
                    .get(b"pcap_set_buffer_size")
                    .map(|f| *f)
                    .expect("pcap_set_buffer_size not loaded"),
                activate: lib
                    .get(b"pcap_activate")
                    .map(|f| *f)
                    .expect("pcap_activate not loaded"),
                open_live: lib
                    .get(b"pcap_open_live")
                    .map(|f| *f)
                    .expect("pcap_open_live not loaded"),
                open_dead: lib
                    .get(b"pcap_open_dead")
                    .map(|f| *f)
                    .expect("pcap_open_dead not loaded"),
                open_offline: lib
                    .get(b"pcap_open_offline")
                    .map(|f| *f)
                    .expect("pcap_open_offline not loaded"),
                #[cfg(not(windows))]
                fopen_offline: lib
                    .get(b"pcap_fopen_offline")
                    .map(|f| *f)
                    .expect("pcap_fopen_offline not loaded"),
                close: lib
                    .get(b"pcap_close")
                    .map(|f| *f)
                    .expect("pcap_close not loaded"),
                r#loop: lib
                    .get(b"pcap_loop")
                    .map(|f| *f)
                    .expect("pcap_loop not loaded"),
                dispatch: lib
                    .get(b"pcap_dispatch")
                    .map(|f| *f)
                    .expect("pcap_dispatch not loaded"),
                next: lib
                    .get(b"pcap_next")
                    .map(|f| *f)
                    .expect("pcap_next not loaded"),
                next_ex: lib
                    .get(b"pcap_next_ex")
                    .map(|f| *f)
                    .expect("pcap_next_ex not loaded"),
                breakloop: lib
                    .get(b"pcap_breakloop")
                    .map(|f| *f)
                    .expect("pcap_breakloop not loaded"),
                stats: lib
                    .get(b"pcap_stats")
                    .map(|f| *f)
                    .expect("pcap_stats not loaded"),
                setfilter: lib
                    .get(b"pcap_setfilter")
                    .map(|f| *f)
                    .expect("pcap_setfilter not loaded"),
                setdirection: lib
                    .get(b"pcap_setdirection")
                    .map(|f| *f)
                    .expect("pcap_setdirection not loaded"),
                getnonblock: lib
                    .get(b"pcap_getnonblock")
                    .map(|f| *f)
                    .expect("pcap_getnonblock not loaded"),
                setnonblock: lib
                    .get(b"pcap_setnonblock")
                    .map(|f| *f)
                    .expect("pcap_setnonblock not loaded"),
                inject: lib.get(b"pcap_inject").map(|f| *f).ok(),
                sendpacket: lib
                    .get(b"pcap_sendpacket")
                    .map(|f| *f)
                    .expect("pcap_sendpacket not loaded"),
                statustostr: lib.get(b"pcap_statustostr").map(|f| *f).ok(),
                strerror: lib
                    .get(b"pcap_strerror")
                    .map(|f| *f)
                    .expect("pcap_strerror not loaded"),
                geterr: lib
                    .get(b"pcap_geterr")
                    .map(|f| *f)
                    .expect("pcap_geterr not loaded"),
                perror: lib
                    .get(b"pcap_perror")
                    .map(|f| *f)
                    .expect("pcap_perror not loaded"),
                compile: lib
                    .get(b"pcap_compile")
                    .map(|f| *f)
                    .expect("pcap_compile not loaded"),
                freecode: lib
                    .get(b"pcap_freecode")
                    .map(|f| *f)
                    .expect("pcap_freecode not loaded"),
                offline_filter: lib
                    .get(b"pcap_offline_filter")
                    .map(|f| *f)
                    .expect("pcap_offline_filter not loaded"),
                datalink: lib
                    .get(b"pcap_datalink")
                    .map(|f| *f)
                    .expect("pcap_datalink not loaded"),
                datalink_ext: lib.get(b"pcap_datalink_ext").map(|f| *f).ok(),
                list_datalinks: lib
                    .get(b"pcap_list_datalinks")
                    .map(|f| *f)
                    .expect("pcap_list_datalinks not loaded"),
                set_datalink: lib
                    .get(b"pcap_set_datalink")
                    .map(|f| *f)
                    .expect("pcap_set_datalink not loaded"),
                free_datalinks: lib
                    .get(b"pcap_free_datalinks")
                    .map(|f| *f)
                    .expect("pcap_free_datalinks not loaded"),
                datalink_name_to_val: lib
                    .get(b"pcap_datalink_name_to_val")
                    .map(|f| *f)
                    .expect("pcap_datalink_name_to_val not loaded"),
                datalink_val_to_name: lib
                    .get(b"pcap_datalink_val_to_name")
                    .map(|f| *f)
                    .expect("pcap_datalink_val_to_name not loaded"),
                datalink_val_to_description: lib
                    .get(b"pcap_datalink_val_to_description")
                    .map(|f| *f)
                    .expect("pcap_datalink_val_to_description not loaded"),
                snapshot: lib
                    .get(b"pcap_snapshot")
                    .map(|f| *f)
                    .expect("pcap_snapshot not loaded"),
                is_swapped: lib
                    .get(b"pcap_is_swapped")
                    .map(|f| *f)
                    .expect("pcap_is_swapped not loaded"),
                major_version: lib
                    .get(b"pcap_major_version")
                    .map(|f| *f)
                    .expect("pcap_major_version not loaded"),
                minor_version: lib
                    .get(b"pcap_minor_version")
                    .map(|f| *f)
                    .expect("pcap_minor_version not loaded"),
                file: lib
                    .get(b"pcap_file")
                    .map(|f| *f)
                    .expect("pcap_file not loaded"),
                fileno: lib
                    .get(b"pcap_fileno")
                    .map(|f| *f)
                    .expect("pcap_fileno not loaded"),
                dump_open: lib
                    .get(b"pcap_dump_open")
                    .map(|f| *f)
                    .expect("pcap_dump_open not loaded"),
                #[cfg(not(windows))]
                dump_fopen: lib
                    .get(b"pcap_dump_fopen")
                    .map(|f| *f)
                    .expect("pcap_dump_fopen not loaded"),
                dump_file: lib
                    .get(b"pcap_dump_file")
                    .map(|f| *f)
                    .expect("pcap_dump_file not loaded"),
                dump_ftell: lib
                    .get(b"pcap_dump_ftell")
                    .map(|f| *f)
                    .expect("pcap_dump_ftell not loaded"),
                dump_flush: lib
                    .get(b"pcap_dump_flush")
                    .map(|f| *f)
                    .expect("pcap_dump_flush not loaded"),
                dump_close: lib
                    .get(b"pcap_dump_close")
                    .map(|f| *f)
                    .expect("pcap_dump_close not loaded"),
                dump: lib
                    .get(b"pcap_dump")
                    .map(|f| *f)
                    .expect("pcap_dump not loaded"),
                findalldevs: lib
                    .get(b"pcap_findalldevs")
                    .map(|f| *f)
                    .expect("pcap_findalldevs not loaded"),
                freealldevs: lib
                    .get(b"pcap_freealldevs")
                    .map(|f| *f)
                    .expect("pcap_freealldevs not loaded"),
                lib_version: lib
                    .get(b"pcap_lib_version")
                    .map(|f| *f)
                    .expect("pcap_lib_version not loaded"),
                bpf_image: lib
                    .get(b"bpf_image")
                    .map(|f| *f)
                    .expect("bpf_image not loaded"),
                bpf_dump: lib
                    .get(b"bpf_dump")
                    .map(|f| *f)
                    .expect("bpf_dump not loaded"),
                #[cfg(not(windows))]
                get_selectable_fd: lib
                    .get(b"pcap_get_selectable_fd")
                    .map(|f| *f)
                    .expect("pcap_get_selectable_fd not loaded"),

                #[cfg(libpcap_1_2)]
                free_tstamp_types: lib
                    .get(b"pcap_free_tstamp_types")
                    .map(|f| *f)
                    .expect("pcap_free_tstamp_types not loaded"),
                #[cfg(libpcap_1_2)]
                list_tstamp_types: lib
                    .get(b"pcap_list_tstamp_types")
                    .map(|f| *f)
                    .expect("pcap_list_tstamp_types not loaded"),
                #[cfg(libpcap_1_2)]
                tstamp_type_name_to_val: lib
                    .get(b"pcap_tstamp_type_name_to_val")
                    .map(|f| *f)
                    .expect("pcap_tstamp_type_name_to_val not loaded"),
                #[cfg(libpcap_1_2)]
                tstamp_type_val_to_description: lib
                    .get(b"pcap_tstamp_type_val_to_description")
                    .map(|f| *f)
                    .expect("pcap_tstamp_type_val_to_description not loaded"),
                #[cfg(libpcap_1_2)]
                tstamp_type_val_to_name: lib
                    .get(b"pcap_tstamp_type_val_to_name")
                    .map(|f| *f)
                    .expect("pcap_tstamp_type_val_to_name not loaded"),
                #[cfg(libpcap_1_2)]
                set_tstamp_type: lib
                    .get(b"pcap_set_tstamp_type")
                    .map(|f| *f)
                    .expect("pcap_set_tstamp_type not loaded"),

                #[cfg(libpcap_1_5)]
                get_tstamp_precision: lib
                    .get(b"pcap_get_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_get_tstamp_precision not loaded"),
                #[cfg(libpcap_1_5)]
                open_dead_with_tstamp_precision: lib
                    .get(b"pcap_open_dead_with_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_open_dead_with_tstamp_precision not loaded"),
                #[cfg(libpcap_1_5)]
                open_offline_with_tstamp_precision: lib
                    .get(b"pcap_open_offline_with_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_open_offline_with_tstamp_precision not loaded"),
                #[cfg(all(not(windows), libpcap_1_5))]
                fopen_offline_with_tstamp_precision: lib
                    .get(b"pcap_fopen_offline_with_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_fopen_offline_with_tstamp_precision not loaded"),
                #[cfg(libpcap_1_5)]
                set_immediate_mode: lib
                    .get(b"pcap_set_immediate_mode")
                    .map(|f| *f)
                    .expect("pcap_set_immediate_mode not loaded"),
                #[cfg(libpcap_1_5)]
                set_tstamp_precision: lib
                    .get(b"pcap_set_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_set_tstamp_precision not loaded"),

                #[cfg(libpcap_1_7)]
                dump_open_append: lib
                    .get(b"pcap_dump_open_append")
                    .map(|f| *f)
                    .expect("pcap_dump_open_append not loaded"),

                #[cfg(libpcap_1_8)]
                oid_get_request: lib
                    .get(b"pcap_oid_get_request")
                    .map(|f| *f)
                    .expect("pcap_oid_get_request not loaded"),
                #[cfg(libpcap_1_8)]
                oid_set_request: lib
                    .get(b"pcap_oid_set_request")
                    .map(|f| *f)
                    .expect("pcap_oid_set_request not loaded"),

                #[cfg(libpcap_1_9)]
                bufsize: lib
                    .get(b"pcap_bufsize")
                    .map(|f| *f)
                    .expect("pcap_bufsize not loaded"),
                #[cfg(libpcap_1_9)]
                createsrcstr: lib
                    .get(b"pcap_createsrcstr")
                    .map(|f| *f)
                    .expect("pcap_createsrcstr not loaded"),
                #[cfg(libpcap_1_9)]
                dump_ftell64: lib
                    .get(b"pcap_dump_ftell64")
                    .map(|f| *f)
                    .expect("pcap_dump_ftell64 not loaded"),
                #[cfg(libpcap_1_9)]
                findalldevs_ex: lib
                    .get(b"pcap_findalldevs_ex")
                    .map(|f| *f)
                    .expect("pcap_findalldevs_ex not loaded"),
                #[cfg(all(libpcap_1_9, not(windows)))]
                get_required_select_timeout: lib
                    .get(b"pcap_get_required_select_timeout")
                    .map(|f| *f)
                    .expect("pcap_get_required_select_timeout not loaded"),
                #[cfg(libpcap_1_9)]
                open: lib
                    .get(b"pcap_open")
                    .map(|f| *f)
                    .expect("pcap_open not loaded"),
                #[cfg(libpcap_1_9)]
                parsesrcstr: lib
                    .get(b"pcap_parsesrcstr")
                    .map(|f| *f)
                    .expect("pcap_parsesrcstr not loaded"),
                #[cfg(libpcap_1_9)]
                remoteact_accept: lib
                    .get(b"pcap_remoteact_accept")
                    .map(|f| *f)
                    .expect("pcap_remoteact_accept not loaded"),
                #[cfg(libpcap_1_9)]
                remoteact_cleanup: lib
                    .get(b"pcap_remoteact_cleanup")
                    .map(|f| *f)
                    .expect("pcap_remoteact_cleanup not loaded"),
                #[cfg(libpcap_1_9)]
                remoteact_close: lib
                    .get(b"pcap_remoteact_close")
                    .map(|f| *f)
                    .expect("pcap_remoteact_close not loaded"),
                #[cfg(libpcap_1_9)]
                remoteact_list: lib
                    .get(b"pcap_remoteact_list")
                    .map(|f| *f)
                    .expect("pcap_remoteact_list not loaded"),
                #[cfg(all(unix, libpcap_1_9))]
                set_protocol_linux: lib
                    .get(b"pcap_set_protocol_linux")
                    .map(|f| *f)
                    .expect("pcap_set_protocol_linux not loaded"),
                #[cfg(libpcap_1_9)]
                setsampling: lib
                    .get(b"pcap_setsampling")
                    .map(|f| *f)
                    .expect("pcap_setsampling not loaded"),

                #[cfg(libpcap_1_10)]
                init: lib
                    .get(b"pcap_init")
                    .map(|f| *f)
                    .expect("pcap_init not loaded"),
                #[cfg(libpcap_1_10)]
                remoteact_accept_ex: lib
                    .get(b"pcap_remoteact_accept_ex")
                    .map(|f| *f)
                    .expect("pcap_remoteact_accept_ex not loaded"),
                #[cfg(libpcap_1_10)]
                datalink_val_to_description_or_dlt: lib
                    .get(b"pcap_datalink_val_to_description_or_dlt")
                    .map(|f| *f)
                    .expect("pcap_datalink_val_to_description_or_dlt not loaded"),

                #[cfg(windows)]
                dump_hopen: lib.get(b"pcap_dump_hopen").map(|f| *f).ok(),
                #[cfg(windows)]
                hopen_offline: lib
                    .get(b"pcap_hopen_offline")
                    .map(|f| *f)
                    .expect("pcap_hopen_offline not loaded"),
                #[cfg(all(windows, libpcap_1_5))]
                hopen_offline_with_tstamp_precision: lib
                    .get(b"pcap_hopen_offline_with_tstamp_precision")
                    .map(|f| *f)
                    .expect("pcap_hopen_offline_with_tstamp_precision not loaded"),
                #[cfg(windows)]
                setbuff: lib
                    .get(b"pcap_setbuff")
                    .map(|f| *f)
                    .expect("pcap_setbuff not loaded"),
                #[cfg(windows)]
                setmode: lib
                    .get(b"pcap_setmode")
                    .map(|f| *f)
                    .expect("pcap_setmode not loaded"),
                #[cfg(windows)]
                setmintocopy: lib
                    .get(b"pcap_setmintocopy")
                    .map(|f| *f)
                    .expect("pcap_setmintocopy not loaded"),
                #[cfg(windows)]
                getevent: lib
                    .get(b"pcap_getevent")
                    .map(|f| *f)
                    .expect("pcap_getevent not loaded"),
                #[cfg(windows)]
                sendqueue_alloc: lib
                    .get(b"pcap_sendqueue_alloc")
                    .map(|f| *f)
                    .expect("pcap_sendqueue_alloc not loaded"),
                #[cfg(windows)]
                sendqueue_destroy: lib
                    .get(b"pcap_sendqueue_destroy")
                    .map(|f| *f)
                    .expect("pcap_sendqueue_destroy not loaded"),
                #[cfg(windows)]
                sendqueue_queue: lib
                    .get(b"pcap_sendqueue_queue")
                    .map(|f| *f)
                    .expect("pcap_sendqueue_queue not loaded"),
                #[cfg(windows)]
                sendqueue_transmit: lib
                    .get(b"pcap_sendqueue_transmit")
                    .map(|f| *f)
                    .expect("pcap_sendqueue_transmit not loaded"),
                #[cfg(windows)]
                stats_ex: lib
                    .get(b"pcap_stats_ex")
                    .map(|f| *f)
                    .expect("pcap_stats_ex not loaded"),
                #[cfg(windows)]
                setuserbuffer: lib
                    .get(b"pcap_setuserbuffer")
                    .map(|f| *f)
                    .expect("pcap_setuserbuffer not loaded"),
                #[cfg(windows)]
                live_dump: lib
                    .get(b"pcap_live_dump")
                    .map(|f| *f)
                    .expect("pcap_live_dump not loaded"),
                #[cfg(windows)]
                live_dump_ended: lib
                    .get(b"pcap_live_dump_ended")
                    .map(|f| *f)
                    .expect("pcap_live_dump_ended not loaded"),
                #[cfg(windows)]
                start_oem: lib.get(b"pcap_start_oem").map(|f| *f).ok(),
                #[cfg(windows)]
                get_airpcap_handle: lib
                    .get(b"pcap_get_airpcap_handle")
                    .map(|f| *f)
                    .expect("pcap_get_airpcap_handle not loaded"),
                _lib: lib,
            })
        }
    }

    /// Get the singleton instance of the API
    pub fn get() -> &'static Api {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<Api> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            #[cfg(windows)]
            add_system_npcap_paths();
            Api::new().expect("Failed to load wpcap")
        })
    }

    #[inline]
    pub unsafe fn lookupnet(
        &self,
        arg1: *const c_char,
        arg2: *mut bpf_u_int32,
        arg3: *mut bpf_u_int32,
        arg4: *mut c_char,
    ) -> c_int {
        (self.lookupnet)(arg1, arg2, arg3, arg4)
    }

    #[inline]
    pub unsafe fn create(&self, arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        (self.create)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_snaplen(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_snaplen)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_promisc(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_promisc)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn can_set_rfmon(&self, arg1: *mut pcap_t) -> c_int {
        self.can_set_rfmon.expect("pcap_can_set_rfmon not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn set_rfmon(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_rfmon.expect("pcap_set_rfmon not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_timeout(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_timeout)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_buffer_size(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_buffer_size)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn activate(&self, arg1: *mut pcap_t) -> c_int {
        (self.activate)(arg1)
    }

    #[inline]
    pub unsafe fn open_live(
        &self,
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut c_char,
    ) -> *mut pcap_t {
        (self.open_live)(arg1, arg2, arg3, arg4, arg5)
    }

    #[inline]
    pub unsafe fn open_dead(&self, arg1: c_int, arg2: c_int) -> *mut pcap_t {
        (self.open_dead)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn open_offline(&self, arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        (self.open_offline)(arg1, arg2)
    }

    #[cfg(not(windows))]
    #[inline]
    pub unsafe fn fopen_offline(&self, arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t {
        (self.fopen_offline)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn close(&self, arg1: *mut pcap_t) {
        (self.close)(arg1)
    }

    #[inline]
    pub unsafe fn r#loop(
        &self,
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int {
        (self.r#loop)(arg1, arg2, arg3, arg4)
    }

    #[inline]
    pub unsafe fn dispatch(
        &self,
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int {
        (self.dispatch)(arg1, arg2, arg3, arg4)
    }

    #[inline]
    pub unsafe fn next(&self, arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar {
        (self.next)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn next_ex(
        &self,
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int {
        (self.next_ex)(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn breakloop(&self, arg1: *mut pcap_t) {
        (self.breakloop)(arg1)
    }

    #[inline]
    pub unsafe fn stats(&self, arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int {
        (self.stats)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setfilter(&self, arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int {
        (self.setfilter)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setdirection(&self, arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int {
        (self.setdirection)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn getnonblock(&self, arg1: *mut pcap_t, arg2: *mut c_char) -> c_int {
        (self.getnonblock)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setnonblock(&self, arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int {
        (self.setnonblock)(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn inject(&self, arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int {
        self.inject.expect("pcap_inject not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn sendpacket(&self, arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int {
        (self.sendpacket)(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn statustostr(&self, arg1: c_int) -> *const c_char {
        self.statustostr.expect("pcap_statustostr not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn strerror(&self, arg1: c_int) -> *const c_char {
        (self.strerror)(arg1)
    }

    #[inline]
    pub unsafe fn geterr(&self, arg1: *mut pcap_t) -> *mut c_char {
        (self.geterr)(arg1)
    }

    #[inline]
    pub unsafe fn perror(&self, arg1: *mut pcap_t, arg2: *const c_char) {
        (self.perror)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn compile(
        &self,
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int {
        (self.compile)(arg1, arg2, arg3, arg4, arg5)
    }

    #[inline]
    pub unsafe fn freecode(&self, arg1: *mut bpf_program) {
        (self.freecode)(arg1)
    }

    #[inline]
    pub unsafe fn offline_filter(
        &self,
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int {
        (self.offline_filter)(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn datalink(&self, arg1: *mut pcap_t) -> c_int {
        (self.datalink)(arg1)
    }

    #[inline]
    pub unsafe fn datalink_ext(&self, arg1: *mut pcap_t) -> c_int {
        self.datalink_ext.expect("pcap_datalink_ext not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn list_datalinks(&self, arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
        (self.list_datalinks)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_datalink(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_datalink)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn free_datalinks(&self, arg1: *mut c_int) {
        (self.free_datalinks)(arg1)
    }

    #[inline]
    pub unsafe fn datalink_name_to_val(&self, arg1: *const c_char) -> c_int {
        (self.datalink_name_to_val)(arg1)
    }

    #[inline]
    pub unsafe fn datalink_val_to_name(&self, arg1: c_int) -> *const c_char {
        (self.datalink_val_to_name)(arg1)
    }

    #[inline]
    pub unsafe fn datalink_val_to_description(&self, arg1: c_int) -> *const c_char {
        (self.datalink_val_to_description)(arg1)
    }

    #[inline]
    pub unsafe fn snapshot(&self, arg1: *mut pcap_t) -> c_int {
        (self.snapshot)(arg1)
    }

    #[inline]
    pub unsafe fn is_swapped(&self, arg1: *mut pcap_t) -> c_int {
        (self.is_swapped)(arg1)
    }

    #[inline]
    pub unsafe fn major_version(&self, arg1: *mut pcap_t) -> c_int {
        (self.major_version)(arg1)
    }

    #[inline]
    pub unsafe fn minor_version(&self, arg1: *mut pcap_t) -> c_int {
        (self.minor_version)(arg1)
    }

    #[inline]
    pub unsafe fn file(&self, arg1: *mut pcap_t) -> *mut FILE {
        (self.file)(arg1)
    }

    #[inline]
    pub unsafe fn fileno(&self, arg1: *mut pcap_t) -> c_int {
        (self.fileno)(arg1)
    }

    #[inline]
    pub unsafe fn dump_open(&self, arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t {
        (self.dump_open)(arg1, arg2)
    }

    #[cfg(not(windows))]
    #[inline]
    pub unsafe fn dump_fopen(&self, arg1: *mut pcap_t, arg2: *mut FILE) -> *mut pcap_dumper_t {
        (self.dump_fopen)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn dump_file(&self, arg1: *mut pcap_dumper_t) -> *mut FILE {
        (self.dump_file)(arg1)
    }

    #[inline]
    pub unsafe fn dump_ftell(&self, arg1: *mut pcap_dumper_t) -> c_long {
        (self.dump_ftell)(arg1)
    }

    #[inline]
    pub unsafe fn dump_flush(&self, arg1: *mut pcap_dumper_t) -> c_int {
        (self.dump_flush)(arg1)
    }

    #[inline]
    pub unsafe fn dump_close(&self, arg1: *mut pcap_dumper_t) {
        (self.dump_close)(arg1)
    }

    #[inline]
    pub unsafe fn dump(&self, arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) {
        (self.dump)(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn findalldevs(&self, arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int {
        (self.findalldevs)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn freealldevs(&self, arg1: *mut pcap_if_t) {
        (self.freealldevs)(arg1)
    }

    #[cfg(not(windows))]
    #[inline]
    pub unsafe fn get_selectable_fd(&self, arg1: *mut pcap_t) -> c_int {
        (self.get_selectable_fd)(arg1)
    }
    #[inline]
    pub unsafe fn lib_version(&self) -> *const c_char {
        (self.lib_version)()
    }

    #[inline]
    pub unsafe fn bpf_image(&self, arg1: *const bpf_insn, arg2: c_int) -> *mut c_char {
        (self.bpf_image)(arg1, arg2)
    }

    #[inline]
    pub unsafe fn bpf_dump(&self, arg1: *const bpf_program, arg2: c_int) {
        (self.bpf_dump)(arg1, arg2)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn free_tstamp_types(&self, arg1: *mut c_int) {
        (self.free_tstamp_types)(arg1)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn list_tstamp_types(&self, arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
        (self.list_tstamp_types)(arg1, arg2)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn tstamp_type_name_to_val(&self, arg1: *const c_char) -> c_int {
        (self.tstamp_type_name_to_val)(arg1)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn tstamp_type_val_to_description(&self, arg1: c_int) -> *const c_char {
        (self.tstamp_type_val_to_description)(arg1)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn tstamp_type_val_to_name(&self, arg1: c_int) -> *const c_char {
        (self.tstamp_type_val_to_name)(arg1)
    }

    #[cfg(libpcap_1_2)]
    #[inline]
    pub unsafe fn set_tstamp_type(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_tstamp_type)(arg1, arg2)
    }

    #[cfg(libpcap_1_5)]
    #[inline]
    pub unsafe fn get_tstamp_precision(&self, arg1: *mut pcap_t) -> c_int {
        (self.get_tstamp_precision)(arg1)
    }

    #[cfg(libpcap_1_5)]
    #[inline]
    pub unsafe fn open_dead_with_tstamp_precision(
        &self,
        arg1: c_int,
        arg2: c_int,
        arg3: c_uint,
    ) -> *mut pcap_t {
        (self.open_dead_with_tstamp_precision)(arg1, arg2, arg3)
    }

    #[cfg(libpcap_1_5)]
    #[inline]
    pub unsafe fn open_offline_with_tstamp_precision(
        &self,
        arg1: *const c_char,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t {
        (self.open_offline_with_tstamp_precision)(arg1, arg2, arg3)
    }

    #[cfg(all(not(windows), libpcap_1_5))]
    #[inline]
    pub unsafe fn fopen_offline_with_tstamp_precision(
        &self,
        arg1: *mut FILE,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t {
        (self.fopen_offline_with_tstamp_precision)(arg1, arg2, arg3)
    }

    #[cfg(libpcap_1_5)]
    #[inline]
    pub unsafe fn set_immediate_mode(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_immediate_mode)(arg1, arg2)
    }

    #[cfg(libpcap_1_5)]
    #[inline]
    pub unsafe fn set_tstamp_precision(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_tstamp_precision)(arg1, arg2)
    }

    #[cfg(libpcap_1_7)]
    #[inline]
    pub unsafe fn dump_open_append(
        &self,
        arg1: *mut pcap_t,
        arg2: *const c_char,
    ) -> *mut pcap_dumper_t {
        (self.dump_open_append)(arg1, arg2)
    }

    #[cfg(libpcap_1_8)]
    #[inline]
    pub unsafe fn oid_get_request(
        &self,
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *mut c_void,
        arg4: *mut size_t,
    ) -> c_int {
        (self.oid_get_request)(arg1, arg2, arg3, arg4)
    }

    #[cfg(libpcap_1_8)]
    #[inline]
    pub unsafe fn oid_set_request(
        &self,
        arg1: *mut pcap_t,
        arg2: bpf_u_int32,
        arg3: *const c_void,
        arg4: *mut size_t,
    ) -> c_int {
        (self.oid_set_request)(arg1, arg2, arg3, arg4)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn bufsize(&self, arg1: *mut pcap_t) -> c_int {
        (self.bufsize)(arg1)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn createsrcstr(
        &self,
        arg1: *mut c_char,
        arg2: c_int,
        arg3: *const c_char,
        arg4: *const c_char,
        arg5: *const c_char,
        arg6: *mut c_char,
    ) -> c_int {
        (self.createsrcstr)(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn dump_ftell64(&self, arg1: *mut pcap_dumper_t) -> i64 {
        (self.dump_ftell64)(arg1)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn findalldevs_ex(
        &self,
        arg1: *const c_char,
        arg2: *mut pcap_rmtauth,
        arg3: *mut *mut pcap_if_t,
        arg4: *mut c_char,
    ) -> c_int {
        (self.findalldevs_ex)(arg1, arg2, arg3, arg4)
    }

    #[cfg(all(libpcap_1_9, not(windows)))]
    #[inline]
    pub unsafe fn get_required_select_timeout(&self, arg1: *mut pcap_t) -> *const timeval {
        (self.get_required_select_timeout)(arg1)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn open(
        &self,
        arg1: *const c_char,
        arg2: c_int,
        arg3: c_int,
        arg4: c_int,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> *mut pcap_t {
        (self.open)(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn parsesrcstr(
        &self,
        arg1: *const c_char,
        arg2: *mut c_int,
        arg3: *mut c_char,
        arg4: *mut c_char,
        arg5: *mut c_char,
        arg6: *mut c_char,
    ) -> c_int {
        (self.parsesrcstr)(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn remoteact_accept(
        &self,
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: *mut c_char,
    ) -> c_int {
        (self.remoteact_accept)(arg1, arg2, arg3, arg4, arg5, arg6)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn remoteact_cleanup(&self) {
        (self.remoteact_cleanup)()
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn remoteact_close(&self, arg1: *const c_char, arg2: *mut c_char) -> c_int {
        (self.remoteact_close)(arg1, arg2)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn remoteact_list(
        &self,
        arg1: *mut c_char,
        arg2: c_char,
        arg3: c_int,
        arg4: *mut c_char,
    ) -> c_int {
        (self.remoteact_list)(arg1, arg2, arg3, arg4)
    }

    #[cfg(all(unix, libpcap_1_9))]
    #[inline]
    pub unsafe fn set_protocol_linux(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.set_protocol_linux)(arg1, arg2)
    }

    #[cfg(libpcap_1_9)]
    #[inline]
    pub unsafe fn setsampling(&self, arg1: *mut pcap_t) -> *mut pcap_samp {
        (self.setsampling)(arg1)
    }

    #[cfg(libpcap_1_10)]
    #[inline]
    pub unsafe fn init(&self, arg1: c_uint, arg2: *mut c_char) -> c_int {
        (self.init)(arg1, arg2)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(libpcap_1_10)]
    #[inline]
    pub unsafe fn remoteact_accept_ex(
        &self,
        arg1: *const c_char,
        arg2: *const c_char,
        arg3: *const c_char,
        arg4: *mut c_char,
        arg5: *mut pcap_rmtauth,
        arg6: c_int,
        arg7: *mut c_char,
    ) -> c_int {
        (self.remoteact_accept_ex)(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
    }

    #[cfg(libpcap_1_10)]
    #[inline]
    pub unsafe fn datalink_val_to_description_or_dlt(&self, arg1: c_int) -> *const c_char {
        (self.datalink_val_to_description_or_dlt)(arg1)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn dump_hopen(&self, arg1: *mut pcap_t, arg2: intptr_t) -> *mut pcap_dumper_t {
        self.dump_hopen.expect("pcap_dump_hopen not loaded")(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn hopen_offline(&self, arg1: intptr_t, arg2: *const c_char) -> *mut pcap_t {
        (self.hopen_offline)(arg1, arg2)
    }

    #[cfg(all(windows, libpcap_1_5))]
    #[inline]
    pub unsafe fn hopen_offline_with_tstamp_precision(
        &self,
        arg1: intptr_t,
        arg2: c_uint,
        arg3: *const c_char,
    ) -> *mut pcap_t {
        (self.hopen_offline_with_tstamp_precision)(arg1, arg2, arg3)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn setbuff(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.setbuff)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn setmode(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.setmode)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn setmintocopy(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.setmintocopy)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn getevent(&self, p: *mut pcap_t) -> HANDLE {
        (self.getevent)(p)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_alloc(&self, memsize: c_uint) -> *mut pcap_send_queue {
        (self.sendqueue_alloc)(memsize)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_destroy(&self, queue: *mut pcap_send_queue) {
        (self.sendqueue_destroy)(queue)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_queue(
        &self,
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> c_int {
        (self.sendqueue_queue)(queue, pkt_header, pkt_data)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_transmit(
        &self,
        p: *mut pcap_t,
        queue: *mut pcap_send_queue,
        sync: c_int,
    ) -> c_uint {
        (self.sendqueue_transmit)(p, queue, sync)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn stats_ex(&self, arg1: *mut pcap_t, arg2: *mut c_int) -> *mut pcap_stat {
        (self.stats_ex)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn setuserbuffer(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.setuserbuffer)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn live_dump(
        &self,
        arg1: *mut pcap_t,
        arg2: *mut c_char,
        arg3: c_int,
        arg4: c_int,
    ) -> c_int {
        (self.live_dump)(arg1, arg2, arg3, arg4)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn live_dump_ended(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        (self.live_dump_ended)(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn start_oem(&self, arg1: *mut c_char, arg2: c_int) -> c_int {
        self.start_oem.expect("pcap_start_oem not loaded")(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn get_airpcap_handle(&self, arg1: *mut pcap_t) -> PAirpcapHandle {
        (self.get_airpcap_handle)(arg1)
    }
}

#[cfg(windows)]
fn add_system_npcap_paths() {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::MAX_PATH;
    use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    unsafe {
        let mut buffer = [0u16; MAX_PATH as usize];
        let len = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
        let path = std::ffi::OsString::from_wide(&buffer[..len as usize]);
        let path = path.to_string_lossy();
        let npcap_path = format!("{}\\Npcap", path);
        let npcap_path = std::ffi::OsStr::new(&npcap_path);
        let mut npcap_path = npcap_path.encode_wide().collect::<Vec<_>>();
        npcap_path.push(0);
        SetDllDirectoryW(npcap_path.as_ptr());
    }
}

#[test]
fn test_api_new() {
    let api = Api::new();
    assert_eq!(api.is_ok(), true);
}
