use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libproc::bsd_info::BSDInfo;
use libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
use libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::proc_pid::{self, listpidinfo, pidinfo};
use libproc::processes::{ProcFilter, pids_by_type};
use sysctl::{CtlValue, Sysctl};

use crate::process::{NetWorkTuple, Network, ProcessError};

pub fn find_process_name(net_tuple: NetWorkTuple) -> Result<(u32, String), ProcessError> {
    let pid = get_pid(net_tuple)?;
    let name = get_exec_path_from_pid(pid)?;
    Ok((pid, name))
}

pub fn find_process_ppid(net_work_tuple: NetWorkTuple) -> Result<(u32, u32), ProcessError> {
    let pid = get_pid(net_work_tuple)?;
    let ppid = get_ppid(pid)?;
    Ok((pid, ppid))
}

/// 根据网络元组查找进程 ID
pub fn get_pid(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let spath = match net_tuple.network {
        Network::Tcp => "net.inet.tcp.pcblist_n",
        Network::Udp => "net.inet.udp.pcblist_n",
    };

    let is_ipv4 = matches!(net_tuple.src_ip, IpAddr::V4(_));

    let v = sysctl::Ctl::new(spath).and_then(|v| v.value())?;
    let buf = match v {
        CtlValue::Struct(data) if !data.is_empty() => data,
        _ => {
            return Err(ProcessError::InvalidData(
                "Expected struct data from sysctl".to_owned(),
            ));
        }
    };

    //todo  struct size  lazy
    let mut item_size = get_struct_size()?;
    if matches!(net_tuple.network, Network::Tcp) {
        item_size += 208; // sizeof(xtcpcb_n)
    }

    let mut fallback_udp_process = String::new();

    // Skip the first xinpgen (24 bytes) block
    let mut i = 24;
    while i + item_size <= buf.len() {
        let inp = i;
        let so = i + 104; // xsocket_n offset

        // Source port (xinpcb_n.inp_lport)
        let src_port = u16::from_be_bytes([buf[inp + 18], buf[inp + 19]]);
        if net_tuple.src_port != src_port {
            i += item_size;
            continue;
        }

        // xinpcb_n.inp_vflag
        let flag = buf[inp + 44];

        let src_ip = match (flag & 0x1 > 0 && is_ipv4, flag & 0x2 > 0 && !is_ipv4) {
            (true, _) => {
                // IPv4
                let addr =
                    Ipv4Addr::new(buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79]);
                Some(IpAddr::V4(addr))
            }
            (_, true) => {
                // IPv6
                let addr_bytes = &buf[inp + 64..inp + 80];
                let addr = Ipv6Addr::from([
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                    addr_bytes[4],
                    addr_bytes[5],
                    addr_bytes[6],
                    addr_bytes[7],
                    addr_bytes[8],
                    addr_bytes[9],
                    addr_bytes[10],
                    addr_bytes[11],
                    addr_bytes[12],
                    addr_bytes[13],
                    addr_bytes[14],
                    addr_bytes[15],
                ]);
                Some(IpAddr::V6(addr))
            }
            _ => None,
        };

        if let Some(src_ip) = src_ip {
            let src_ip = match src_ip {
                IpAddr::V4(addr) => IpAddr::V4(addr),
                IpAddr::V6(addr) => IpAddr::V6(addr.octets().into()),
            };

            if net_tuple.src_ip == src_ip {
                // xsocket_n.so_last_pid
                let pid =
                    u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
                return Ok(pid);
            }

            // UDP fallback for unspecified IP
            if matches!(net_tuple.network, Network::Udp)
                && (src_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    || src_ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                && is_ipv4 == matches!(src_ip, IpAddr::V4(_))
            {
                let pid =
                    u32::from_ne_bytes([buf[so + 68], buf[so + 69], buf[so + 70], buf[so + 71]]);
                if let Ok(path) = get_exec_path_from_pid(pid) {
                    fallback_udp_process = path;
                }
            }
        }

        i += item_size;
    }

    if matches!(net_tuple.network, Network::Udp) && !fallback_udp_process.is_empty() {
        // For UDP, we return PID 0 and the fallback path
        return Ok(0);
    }

    Err(ProcessError::NotFound)
}

pub fn get_ppid(pid: u32) -> Option<u32> {
    unsafe {
        let info = pidinfo::<libproc::libproc::proc_pid::ProcPIDInfo>(pid as i32, 0)?;
        Some(info.ppi.ppid as u32)
    }
}

// Determine structure size based on macOS version
fn get_struct_size() -> Result<usize, ProcessError> {
    let os_release = sysctl::Ctl::new("kern.osrelease")?;
    let major = os_release
        .value_string()?
        .split('.')
        .next()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);

    match major >= 22 {
        true => Ok(408),
        false => Ok(384),
    }
}

/// 根据 PID 获取进程可执行文件的路径
fn get_exec_path_from_pid(pid: u32) -> Result<String, ProcessError> {
    proc_pid::pidpath(pid as i32).map_err(|e| ProcessError::NameReadError(e))
}

#[allow(dead_code)]
fn get_pid_by_source_ip_port(source_ip: IpAddr, source_port: u16) -> Result<u32, ProcessError> {
    let current_uid: libc::uid_t = unsafe { libc::getuid() };
    let proc_filter = match current_uid == 0 {
        true => ProcFilter::All,
        false => ProcFilter::ByRealUID { ruid: current_uid },
    };

    let pids = pids_by_type(proc_filter)?;

    // 遍历每个进程
    for pid in pids {
        // 获取进程的所有 socket 文件描述符
        if let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) {
            if let Ok(fds) = listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize) {
                for fd in &fds {
                    if let ProcFDType::Socket = fd.proc_fdtype.into() {
                        if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) {
                            if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                                let info = unsafe { socket.psi.soi_proto.pri_tcp };
                                let local_port = u16::from_be(info.tcpsi_ini.insi_lport as u16);
                                if local_port != source_port {
                                    continue;
                                }
                                let local_ip = match info.tcpsi_ini.insi_vflag {
                                    vflag if vflag & 0x1 > 0 => {
                                        let addr = unsafe {
                                            info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr
                                        };
                                        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
                                    }
                                    vflag if vflag & 0x2 > 0 => {
                                        let addr =
                                            unsafe { info.tcpsi_ini.insi_laddr.ina_6.s6_addr };
                                        IpAddr::V6(Ipv6Addr::from(addr))
                                    }
                                    _ => continue,
                                };

                                if local_ip == source_ip {
                                    return Ok(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(ProcessError::NotFound)
}
