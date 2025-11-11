use std::fs::{self, DirEntry};
use std::io::{self};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::process::{NetWorkTuple, Network, ProcessError};

/// 根据本地 IP 和端口获取进程 ID（PID）。
/// 返回 `Ok(Some(pid))` 如果找到，`Ok(None)` 如果未找到，`Err` 如果出错。
pub fn find_process_name(net_tuple: NetWorkTuple) -> Result<(u32, String), ProcessError> {
    let pid = get_pid(net_tuple)?;
    let name = get_process_name(pid)?;
    Ok((pid, name))
}

pub fn find_process_ppid(net_tuple: NetWorkTuple) -> Result<(u32, u32), ProcessError> {
    let pid = get_pid(net_tuple)?;
    let ppid = get_ppid(pid)?;
    Ok((pid, ppid))
}

pub fn get_pid(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let socket = get_inode_by_netlink(net_tuple)?;
    if socket.0 == 0 {
        return Err(ProcessError::NotFound); // 未找到匹配的套接字
    }
    let pid = get_pid_by_inode(socket.0, socket.1)?.ok_or(ProcessError::NotFound)?;
    Ok((pid))
}

fn get_inode_by_netlink(net_tuple: NetWorkTuple) -> Result<(u32, u32), ProcessError> {
    let NetWorkTuple {
        network,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    } = net_tuple;

    // 创建 Netlink socket
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    let addr = SocketAddr::new(0, 0);
    socket.bind_auto()?;
    socket.connect(&addr)?;
    // 构建请求
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    header.message_type = SOCK_DIAG_BY_FAMILY;

    let sockid = SocketId {
        source_port: src_port,
        destination_port: dst_port,
        source_address: src_ip,
        destination_address: dst_ip,
        interface_id: 0,
        cookie: [0; 8],
    };

    let protocol = match network {
        Network::Tcp => IPPROTO_TCP,
        Network::Udp => IPPROTO_UDP,
    };

    let req = InetRequest {
        family: AF_INET,
        protocol,
        extensions: ExtensionFlags::INFO,
        states: StateFlags::ESTABLISHED, //
        socket_id: sockid,
    };

    let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(req).into());

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);

    if let Err(e) = socket.send(&buf[..], 0) {
        return Err(ProcessError::IoError(e));
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    let mut inode = 0u32;
    let mut uid = 0u32;

    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0)?;
        loop {
            let bytes = &receive_buffer[offset..];

            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if let NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(msg)) =
                rx_packet.payload
            {
                let head = &msg.header;
                let socket = &head.socket_id;

                if socket.source_port == src_port && socket.source_address == src_ip {
                    inode = head.inode;
                    uid = head.uid;
                    break;
                }
            }

            offset += rx_packet.header.length as usize;
            if offset >= size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
        if inode != 0 {
            break;
        }
    }

    Ok((inode, uid))
}

// 根据 inode 查找 PID，使用并行处理
fn get_pid_by_inode(inode: u32, uid: u32) -> Result<Option<u32>, ProcessError> {
    let socket = format!("socket:[{}]", inode);
    let socket_bytes = socket.as_bytes();

    let proc_dirs: Vec<DirEntry> = fs::read_dir("/proc")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            // 过滤非目录或非 PID 命名的目录
            entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) &&
            is_valid_pid(entry.file_name().as_os_str().as_bytes()) &&
            // 仅检查匹配 UID 的进程
            entry.metadata().map(|meta| meta.uid() == uid).unwrap_or(false)
        })
        .collect();

    // 使用 rayon 并行查找
    let pid = proc_dirs.par_iter().find_map_any(|dir| {
        let name = dir.file_name();

        let name_str = match name.to_str() {
            Some(name_str) => name_str,
            None => return None,
        };

        let fd_path = dir.path().join("fd");

        let fd_entries = match fs::read_dir(fd_path) {
            Ok(entries) => entries.filter_map(|fd| fd.ok()).collect::<Vec<_>>(),
            Err(_) => return None,
        };

        let found = fd_entries.par_iter().find_map_any(|link| {
            if let Ok(path) = fs::read_link(link.path()) {
                if path.as_os_str().as_bytes() == socket_bytes {
                    return Some(name_str.parse::<u32>().ok()?);
                }
            }
            None
        });

        found
    });

    Ok(pid)
}

// 高效的 PID 检查
fn is_valid_pid(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 10 {
        return false;
    }

    if name[0] == b'0' && name.len() > 1 {
        return false; // 避免前导零
    }
    name.iter().all(|&b| b.is_ascii_digit())
}

/// 根据 PID 获取进程可执行文件的路径。
/// 返回 `Ok(Some(path))` 如果找到，`Ok(None)` 如果未找到，`Err` 如果出错。
pub fn get_process_name(pid: u32) -> Result<String, ProcessError> {
    libproc::proc_pid::pidpath(pid as i32).map_err(|e| ProcessError::NameReadError(e))
}

/// 根据进程 ID 获取父进程 ID
pub fn get_ppid(pid: u32) -> Result<u32, ProcessError> {
    let path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(&path).map_err(|e| ProcessError::IoError(e))?;

    // stat 文件的格式是空格分隔的字段
    // 第4个字段(索引为3)是父进程ID
    let fields: Vec<&str> = content.split_whitespace().collect();
    if fields.len() < 4 {
        return Err(ProcessError::NotFound);
    }

    fields[3]
        .parse::<u32>()
        .map_err(|_| ProcessError::InvalidData("Failed to parse PPID".to_string()))
}
