use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: usize,
    minor: usize,
    micro: usize,
}

impl Version {
    const LOWEST_SUPPORTED: Self = Self {
        major: 1,
        minor: 0,
        micro: 0,
    };

    fn new(major: usize, minor: usize, micro: usize) -> Version {
        Version {
            major,
            minor,
            micro,
        }
    }

    fn list() -> Vec<Version> {
        vec![
            Version::new(1, 0, 0),
            Version::new(1, 2, 1),
            Version::new(1, 5, 0),
            Version::new(1, 7, 2),
            Version::new(1, 9, 0),
            Version::new(1, 9, 1),
            Version::new(1, 10, 0),
        ]
    }

    fn max() -> Version {
        Version::new(1, 10, 0)
    }

    #[allow(dead_code)]
    fn parse(s: &str) -> Result<Version, Box<dyn std::error::Error>> {
        let err = format!("invalid pcap lib version: {}", s);

        let re = regex::Regex::new(r"([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(s).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Version {
            major,
            minor,
            micro,
        } = self;
        write!(f, "{}.{}.{}", major, minor, micro)
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

#[cfg(windows)]
fn find_system_npcap() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let windir = env::var("WINDIR")?;
    let npcap = PathBuf::from(windir).join("System32").join("Npcap");
    let wpcap_dll = npcap.join("wpcap.dll");
    if wpcap_dll.exists() {
        add_system_npcap_paths();
        Ok(wpcap_dll)
    } else {
        Err("npcap not found".into())
    }
}

fn get_libpcap_version(libdirpath: Option<PathBuf>) -> Result<Version, Box<dyn std::error::Error>> {
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut libfile = PathBuf::from("libpcap.so");
    #[cfg(target_os = "macos")]
    let mut libfile = PathBuf::from("libpcap.dylib");
    #[cfg(windows)]
    let mut libfile = find_system_npcap()?;

    if let Some(libdir) = libdirpath {
        libfile = libdir.join(libfile);
    }

    let lib = if let Ok(lib) = unsafe { libloading::Library::new(libfile) } {
        lib
    } else {
        return Ok(Version::max());
    };

    type PcapLibVersion = unsafe extern "C" fn() -> *mut c_char;
    let pcap_lib_version = unsafe { lib.get::<PcapLibVersion>(b"pcap_lib_version")? };

    let c_buf: *const c_char = unsafe { pcap_lib_version() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let v_str: &str = c_str.to_str()?;

    let err = format!("cannot infer pcap lib version from: {}", v_str);

    #[cfg(not(windows))]
    {
        let re =
            regex::Regex::new(r"libpcap version ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }

    #[cfg(windows)]
    {
        let re = regex::Regex::new(r"based on libpcap version ([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            0,
        ))
    }
}

#[cfg(any(
    feature = "pcap_1_0",
    feature = "pcap_1_2",
    feature = "pcap_1_5",
    feature = "pcap_1_7",
    feature = "pcap_1_8",
    feature = "pcap_1_9",
    feature = "pcap_1_10"
))]
fn emit_cfg_flags(_version: Version) {
    #[cfg(feature = "pcap_1_0")]
    println!("cargo:rustc-cfg=libpcap_1_0");

    #[cfg(feature = "pcap_1_2")]
    println!("cargo:rustc-cfg=libpcap_1_2");

    #[cfg(feature = "pcap_1_5")]
    println!("cargo:rustc-cfg=libpcap_1_5");

    #[cfg(feature = "pcap_1_7")]
    println!("cargo:rustc-cfg=libpcap_1_7");

    #[cfg(feature = "pcap_1_8")]
    println!("cargo:rustc-cfg=libpcap_1_8");

    #[cfg(feature = "pcap_1_9")]
    println!("cargo:rustc-cfg=libpcap_1_9");

    #[cfg(feature = "pcap_1_10")]
    println!("cargo:rustc-cfg=libpcap_1_10");
}

#[cfg(not(any(
    feature = "pcap_1_0",
    feature = "pcap_1_2",
    feature = "pcap_1_5",
    feature = "pcap_1_7",
    feature = "pcap_1_8",
    feature = "pcap_1_9",
    feature = "pcap_1_10"
)))]
fn emit_cfg_flags(version: Version) {
    assert!(
        version >= Version::LOWEST_SUPPORTED,
        "required pcap lib version: >=1.0.0"
    );

    println!("cargo:warning=libpcap version: {}", version);

    for v in Version::list().iter().filter(|&v| v <= &version) {
        println!("cargo:rustc-cfg=libpcap_{}_{}", v.major, v.minor);
    }
}

fn main() {
    if let Ok(version) = get_libpcap_version(None) {
        emit_cfg_flags(version);
    } else {
        emit_cfg_flags(Version::max());
    }
}
