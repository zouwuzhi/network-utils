use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};
use thiserror::Error;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// 重新导出 find_process_name
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::{find_process_name, find_process_ppid, get_pid, get_ppid};
#[cfg(target_os = "macos")]
pub use macos::{find_process_name, find_process_ppid, get_pid, get_ppid};
#[cfg(target_os = "windows")]
pub use windows::{find_process_name, find_process_ppid, get_pid, get_ppid};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct NetWorkTuple {
    network: Network,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

impl Default for NetWorkTuple {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 0,
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 0,
        }
    }
}

impl NetWorkTuple {
    pub fn new(src_ip: IpAddr, src_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            ..Default::default()
        }
    }

    pub fn new_tcp(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            network: Network::Tcp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    pub fn is_v4(&self) -> bool {
        self.src_ip.is_ipv4()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("InvalidData:{0}")]
    InvalidData(String),

    #[error("notfound")]
    NotFound,

    #[cfg(target_os = "macos")]
    #[error("sysctl read error:{0}")]
    SysctlError(#[from] sysctl::SysctlError),

    #[error("name read error:{0}")]
    NameReadError(String),

    #[error("io error:{0}")]
    IoError(#[from] io::Error),
}
