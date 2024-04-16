use crate::raw::{
    bpf_program, pcap_direction_t, pcap_dumper_t, pcap_handler, pcap_if_t, pcap_pkthdr,
    pcap_send_queue, pcap_stat, pcap_t,
};
use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, c_void, sockaddr, timeval, FILE};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

pub mod ffi {
    use super::*;

    pub type PcapCreate =
        unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub type PcapSetSnaplen = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetPromisc = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetTimeout = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapSetBufferSize = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapActivate = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapOpenDead = unsafe extern "C" fn(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub type PcapOpenOffline =
        unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub type PcapFopenOffline =
        unsafe extern "C" fn(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
    pub type PcapClose = unsafe extern "C" fn(arg1: *mut pcap_t);
    pub type PcapLoop = unsafe extern "C" fn(
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int;
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
    pub type PcapSetnonblock =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
    pub type PcapSendpacket =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
    pub type PcapGeterr = unsafe extern "C" fn(arg1: *mut pcap_t) -> *mut c_char;
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
    pub type PcapListDatalinks =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    pub type PcapSetDatalink = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub type PcapFreeDatalinks = unsafe extern "C" fn(arg1: *mut c_int);
    pub type PcapDatalinkNameToVal = unsafe extern "C" fn(arg1: *const c_char) -> c_int;
    pub type PcapDatalinkValToName = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapDatalinkValToDescription = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
    pub type PcapMajorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapMinorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapFileno = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
    pub type PcapDumpOpen =
        unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
    pub type PcapDumpFopen =
        unsafe extern "C" fn(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
    pub type PcapDumpFlush = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> c_int;
    pub type PcapDumpClose = unsafe extern "C" fn(arg1: *mut pcap_dumper_t);
    pub type PcapDump =
        unsafe extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
    pub type PcapFindalldevs =
        unsafe extern "C" fn(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
    pub type PcapFreealldevs = unsafe extern "C" fn(arg1: *mut pcap_if_t);
    pub type PcapGetSelectableFd = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;

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
}

pub struct Api {
    pub create: Option<ffi::PcapCreate>,
    pub set_snaplen: Option<ffi::PcapSetSnaplen>,
    pub set_promisc: Option<ffi::PcapSetPromisc>,
    pub set_timeout: Option<ffi::PcapSetTimeout>,
    pub set_buffer_size: Option<ffi::PcapSetBufferSize>,
    pub activate: Option<ffi::PcapActivate>,
    pub open_dead: Option<ffi::PcapOpenDead>,
    pub open_offline: Option<ffi::PcapOpenOffline>,
    pub fopen_offline: Option<ffi::PcapFopenOffline>,
    pub close: Option<ffi::PcapClose>,
    pub r#loop: Option<ffi::PcapLoop>,
    pub next_ex: Option<ffi::PcapNextEx>,
    pub breakloop: Option<ffi::PcapBreakloop>,
    pub stats: Option<ffi::PcapStats>,
    pub setfilter: Option<ffi::PcapSetfilter>,
    pub setdirection: Option<ffi::PcapSetdirection>,
    pub setnonblock: Option<ffi::PcapSetnonblock>,
    pub sendpacket: Option<ffi::PcapSendpacket>,
    pub geterr: Option<ffi::PcapGeterr>,
    pub compile: Option<ffi::PcapCompile>,
    pub freecode: Option<ffi::PcapFreecode>,
    pub offline_filter: Option<ffi::PcapOfflineFilter>,
    pub datalink: Option<ffi::PcapDatalink>,
    pub list_datalinks: Option<ffi::PcapListDatalinks>,
    pub set_datalink: Option<ffi::PcapSetDatalink>,
    pub free_datalinks: Option<ffi::PcapFreeDatalinks>,
    pub datalink_name_to_val: Option<ffi::PcapDatalinkNameToVal>,
    pub datalink_val_to_name: Option<ffi::PcapDatalinkValToName>,
    pub datalink_val_to_description: Option<ffi::PcapDatalinkValToDescription>,
    pub major_version: Option<ffi::PcapMajorVersion>,
    pub minor_version: Option<ffi::PcapMinorVersion>,
    pub fileno: Option<ffi::PcapFileno>,
    pub dump_open: Option<ffi::PcapDumpOpen>,
    pub dump_fopen: Option<ffi::PcapDumpFopen>,
    pub dump_flush: Option<ffi::PcapDumpFlush>,
    pub dump_close: Option<ffi::PcapDumpClose>,
    pub dump: Option<ffi::PcapDump>,
    pub findalldevs: Option<ffi::PcapFindalldevs>,
    pub freealldevs: Option<ffi::PcapFreealldevs>,
    pub get_selectable_fd: Option<ffi::PcapGetSelectableFd>,
    #[cfg(windows)]
    pub setmintocopy: Option<ffi::PcapSetmintocopy>,
    #[cfg(windows)]
    pub getevent: Option<ffi::PcapGetEvent>,
    #[cfg(windows)]
    pub sendqueue_alloc: Option<ffi::PcapSendQueueAlloc>,
    #[cfg(windows)]
    pub sendqueue_destroy: Option<ffi::PcapSendQueueDestroy>,
    #[cfg(windows)]
    pub sendqueue_queue: Option<ffi::PcapSendQueueQueue>,
    #[cfg(windows)]
    pub sendqueue_transmit: Option<ffi::PcapSendQueueTransmit>,
    _lib: libloading::Library,
}

impl Api {
    pub fn new() -> Result<Self, libloading::Error> {
        unsafe {
            let lib = libloading::Library::new("C:\\WINDOWS\\system32\\Npcap\\wpcap.dll")?;
            Ok(Self {
                create: lib.get(b"pcap_create").map(|f| *f).ok(),
                set_snaplen: lib.get(b"pcap_setsnaplen").map(|f| *f).ok(),
                set_promisc: lib.get(b"pcap_setpromisc").map(|f| *f).ok(),
                set_timeout: lib.get(b"pcap_settimeout").map(|f| *f).ok(),
                set_buffer_size: lib.get(b"pcap_setbuff").map(|f| *f).ok(),
                activate: lib.get(b"pcap_activate").map(|f| *f).ok(),
                open_dead: lib.get(b"pcap_open_dead").map(|f| *f).ok(),
                open_offline: lib.get(b"pcap_open_offline").map(|f| *f).ok(),
                fopen_offline: lib.get(b"pcap_fopen_offline").map(|f| *f).ok(),
                close: lib.get(b"pcap_close").map(|f| *f).ok(),
                r#loop: lib.get(b"pcap_loop").map(|f| *f).ok(),
                next_ex: lib.get(b"pcap_next_ex").map(|f| *f).ok(),
                breakloop: lib.get(b"pcap_breakloop").map(|f| *f).ok(),
                stats: lib.get(b"pcap_stats").map(|f| *f).ok(),
                setfilter: lib.get(b"pcap_setfilter").map(|f| *f).ok(),
                setdirection: lib.get(b"pcap_setdirection").map(|f| *f).ok(),
                setnonblock: lib.get(b"pcap_setnonblock").map(|f| *f).ok(),
                sendpacket: lib.get(b"pcap_sendpacket").map(|f| *f).ok(),
                geterr: lib.get(b"pcap_geterr").map(|f| *f).ok(),
                compile: lib.get(b"pcap_compile").map(|f| *f).ok(),
                freecode: lib.get(b"pcap_freecode").map(|f| *f).ok(),
                offline_filter: lib.get(b"pcap_offline_filter").map(|f| *f).ok(),
                datalink: lib.get(b"pcap_datalink").map(|f| *f).ok(),
                list_datalinks: lib.get(b"pcap_list_datalinks").map(|f| *f).ok(),
                set_datalink: lib.get(b"pcap_set_datalink").map(|f| *f).ok(),
                free_datalinks: lib.get(b"pcap_free_datalinks").map(|f| *f).ok(),
                datalink_name_to_val: lib.get(b"pcap_datalink_name_to_val").map(|f| *f).ok(),
                datalink_val_to_name: lib.get(b"pcap_datalink_val_to_name").map(|f| *f).ok(),
                datalink_val_to_description: lib
                    .get(b"pcap_datalink_val_to_description")
                    .map(|f| *f)
                    .ok(),
                major_version: lib.get(b"pcap_major_version").map(|f| *f).ok(),
                minor_version: lib.get(b"pcap_minor_version").map(|f| *f).ok(),
                fileno: lib.get(b"pcap_fileno").map(|f| *f).ok(),
                dump_open: lib.get(b"pcap_dump_open").map(|f| *f).ok(),
                dump_fopen: lib.get(b"pcap_dump_fopen").map(|f| *f).ok(),
                dump_flush: lib.get(b"pcap_dump_flush").map(|f| *f).ok(),
                dump_close: lib.get(b"pcap_dump_close").map(|f| *f).ok(),
                dump: lib.get(b"pcap_dump").map(|f| *f).ok(),
                findalldevs: lib.get(b"pcap_findalldevs").map(|f| *f).ok(),
                freealldevs: lib.get(b"pcap_freealldevs").map(|f| *f).ok(),
                get_selectable_fd: lib.get(b"pcap_get_selectable_fd").map(|f| *f).ok(),
                #[cfg(windows)]
                setmintocopy: lib.get(b"pcap_setmintocopy").map(|f| *f).ok(),
                #[cfg(windows)]
                getevent: lib.get(b"pcap_getevent").map(|f| *f).ok(),
                #[cfg(windows)]
                sendqueue_alloc: lib.get(b"pcap_sendqueue_alloc").map(|f| *f).ok(),
                #[cfg(windows)]
                sendqueue_destroy: lib.get(b"pcap_sendqueue_destroy").map(|f| *f).ok(),
                #[cfg(windows)]
                sendqueue_queue: lib.get(b"pcap_sendqueue_queue").map(|f| *f).ok(),
                #[cfg(windows)]
                sendqueue_transmit: lib.get(b"pcap_sendqueue_transmit").map(|f| *f).ok(),
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
    pub unsafe fn create(&self, arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        self.create.expect("pcap_create not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_snaplen(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_snaplen.expect("pcap_setsnaplen not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_promisc(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_promisc.expect("pcap_setpromisc not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_timeout(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_timeout.expect("pcap_settimeout not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_buffer_size(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_buffer_size.expect("pcap_setbuff not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn activate(&self, arg1: *mut pcap_t) -> c_int {
        self.activate.expect("pcap_activate not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn open_dead(&self, arg1: c_int, arg2: c_int) -> *mut pcap_t {
        self.open_dead.expect("pcap_open_dead not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn open_offline(&self, arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
        self.open_offline.expect("pcap_open_offline not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn fopen_offline(&self, arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t {
        self.fopen_offline.expect("pcap_fopen_offline not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn close(&self, arg1: *mut pcap_t) {
        self.close.expect("pcap_close not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn r#loop(
        &self,
        arg1: *mut pcap_t,
        arg2: c_int,
        arg3: pcap_handler,
        arg4: *mut c_uchar,
    ) -> c_int {
        self.r#loop.expect("pcap_loop not loaded")(arg1, arg2, arg3, arg4)
    }

    #[inline]
    pub unsafe fn next_ex(
        &self,
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int {
        self.next_ex.expect("pcap_next_ex not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn breakloop(&self, arg1: *mut pcap_t) {
        self.breakloop.expect("pcap_breakloop not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn stats(&self, arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int {
        self.stats.expect("pcap_stats not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setfilter(&self, arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int {
        self.setfilter.expect("pcap_setfilter not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setdirection(&self, arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int {
        self.setdirection.expect("pcap_setdirection not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn setnonblock(&self, arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int {
        self.setnonblock.expect("pcap_setnonblock not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn sendpacket(&self, arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int {
        self.sendpacket.expect("pcap_sendpacket not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn geterr(&self, arg1: *mut pcap_t) -> *mut c_char {
        self.geterr.expect("pcap_geterr not loaded")(arg1)
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
        self.compile.expect("pcap_compile not loaded")(arg1, arg2, arg3, arg4, arg5)
    }

    #[inline]
    pub unsafe fn freecode(&self, arg1: *mut bpf_program) {
        self.freecode.expect("pcap_freecode not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn offline_filter(
        &self,
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int {
        self.offline_filter.expect("pcap_offline_filter not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn datalink(&self, arg1: *mut pcap_t) -> c_int {
        self.datalink.expect("pcap_datalink not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn list_datalinks(&self, arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
        self.list_datalinks.expect("pcap_list_datalinks not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn set_datalink(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.set_datalink.expect("pcap_set_datalink not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn free_datalinks(&self, arg1: *mut c_int) {
        self.free_datalinks.expect("pcap_free_datalinks not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn datalink_name_to_val(&self, arg1: *const c_char) -> c_int {
        self.datalink_name_to_val
            .expect("pcap_datalink_name_to_val not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn datalink_val_to_name(&self, arg1: c_int) -> *const c_char {
        self.datalink_val_to_name
            .expect("pcap_datalink_val_to_name not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn datalink_val_to_description(&self, arg1: c_int) -> *const c_char {
        self.datalink_val_to_description
            .expect("pcap_datalink_val_to_description not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn major_version(&self, arg1: *mut pcap_t) -> c_int {
        self.major_version.expect("pcap_major_version not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn minor_version(&self, arg1: *mut pcap_t) -> c_int {
        self.minor_version.expect("pcap_minor_version not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn fileno(&self, arg1: *mut pcap_t) -> c_int {
        self.fileno.expect("pcap_fileno not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn dump_open(&self, arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t {
        self.dump_open.expect("pcap_dump_open not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn dump_fopen(&self, arg1: *mut pcap_t, arg2: *mut FILE) -> *mut pcap_dumper_t {
        self.dump_fopen.expect("pcap_dump_fopen not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn dump_flush(&self, arg1: *mut pcap_dumper_t) -> c_int {
        self.dump_flush.expect("pcap_dump_flush not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn dump_close(&self, arg1: *mut pcap_dumper_t) {
        self.dump_close.expect("pcap_dump_close not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn dump(&self, arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) {
        self.dump.expect("pcap_dump not loaded")(arg1, arg2, arg3)
    }

    #[inline]
    pub unsafe fn findalldevs(&self, arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int {
        self.findalldevs.expect("pcap_findalldevs not loaded")(arg1, arg2)
    }

    #[inline]
    pub unsafe fn freealldevs(&self, arg1: *mut pcap_if_t) {
        self.freealldevs.expect("pcap_freealldevs not loaded")(arg1)
    }

    #[inline]
    pub unsafe fn get_selectable_fd(&self, arg1: *mut pcap_t) -> c_int {
        self.get_selectable_fd
            .expect("pcap_get_selectable_fd not loaded")(arg1)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn setmintocopy(&self, arg1: *mut pcap_t, arg2: c_int) -> c_int {
        self.setmintocopy.expect("pcap_setmintocopy not loaded")(arg1, arg2)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn getevent(&self, p: *mut pcap_t) -> HANDLE {
        self.getevent.expect("pcap_getevent not loaded")(p)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_alloc(&self, memsize: c_uint) -> *mut pcap_send_queue {
        self.sendqueue_alloc
            .expect("pcap_sendqueue_alloc not loaded")(memsize)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_destroy(&self, queue: *mut pcap_send_queue) {
        self.sendqueue_destroy
            .expect("pcap_sendqueue_destroy not loaded")(queue)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_queue(
        &self,
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> c_int {
        self.sendqueue_queue
            .expect("pcap_sendqueue_queue not loaded")(queue, pkt_header, pkt_data)
    }

    #[cfg(windows)]
    #[inline]
    pub unsafe fn sendqueue_transmit(
        &self,
        p: *mut pcap_t,
        queue: *mut pcap_send_queue,
        sync: c_int,
    ) -> c_uint {
        self.sendqueue_transmit
            .expect("pcap_sendqueue_transmit not loaded")(p, queue, sync)
    }
}

#[cfg(windows)]
fn add_system_npcap_paths() {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::{GetLastError, MAX_PATH};
    use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    unsafe {
        let mut buffer = [0u16; MAX_PATH as usize];
        let len = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32);
        println!("{:x}", GetLastError());
        let path = std::ffi::OsString::from_wide(&buffer[..len as usize]);
        let path = path.to_string_lossy();
        let npcap_path = format!("{}\\Npcap", path);
        let npcap_path = std::ffi::OsStr::new(&npcap_path);
        println!("{:?}", npcap_path);
        let mut npcap_path = npcap_path.encode_wide().collect::<Vec<_>>();
        npcap_path.push(0);
        SetDllDirectoryW(npcap_path.as_ptr());
        println!("{:x}", GetLastError());
    }
}

#[test]
fn test_api_new() {
    let api = Api::new();
    assert_eq!(api.is_ok(), true);
}
