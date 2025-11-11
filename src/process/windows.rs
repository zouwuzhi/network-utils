use crate::process::{NetWorkTuple, Network, ProcessError};
use std::ffi::c_void;
use std::mem;
use std::net::IpAddr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// 根据网络元组获取进程 ID 和名称
pub fn find_process_name(net_tuple: NetWorkTuple) -> Result<(u32, String), ProcessError> {
    let pid = get_pid(net_tuple)?;
    let name = get_process_path(pid)?;
    Ok((pid, name))
}

pub fn find_process_ppid(net_tuple: NetWorkTuple) -> Result<(u32, u32), ProcessError> {
    let pid = get_pid(net_tuple)?;
    let ppid = get_ppid(pid)?;
    Ok((pid, ppid))
}

/// 根据网络元组查找进程 ID
pub fn get_pid(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    match net_tuple.network {
        Network::Tcp => get_pid_by_tcp_net(net_tuple),
        Network::Udp => get_pid_by_udp_net(net_tuple),
    }
}

/// 获取 TCP 网络连接的进程 ID
fn get_pid_by_tcp_net(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let af_inet = get_address_family(&net_tuple);

    // 获取 TCP 表数据
    let buffer = get_extended_tcp_table(af_inet)?;

    match net_tuple.src_ip {
        IpAddr::V4(src_ip) => search_tcp_v4_pid(&buffer, src_ip, net_tuple.src_port),
        IpAddr::V6(src_ip) => search_tcp_v6_pid(&buffer, src_ip, net_tuple.src_port),
    }
}

/// 获取 UDP 网络连接的进程 ID
fn get_pid_by_udp_net(net_tuple: NetWorkTuple) -> Result<u32, ProcessError> {
    let af_inet = get_address_family(&net_tuple);

    // 获取 UDP 表数据
    let buffer = get_extended_udp_table(af_inet)?;

    match net_tuple.src_ip {
        IpAddr::V4(src_ip) => search_udp_v4_pid(&buffer, src_ip, net_tuple.src_port),
        IpAddr::V6(src_ip) => search_udp_v6_pid(&buffer, src_ip, net_tuple.src_port),
    }
}

/// 获取地址族
fn get_address_family(net_tuple: &NetWorkTuple) -> u32 {
    if net_tuple.is_v4() {
        AF_INET as u32
    } else {
        AF_INET6 as u32
    }
}

/// 获取扩展 TCP 表
fn get_extended_tcp_table(af_inet: u32) -> Result<Vec<u8>, ProcessError> {
    let mut buffer_size: u32 = 0;

    // 第一次调用获取所需缓冲区大小
    let result = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut buffer_size,
            0, // false
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    // 检查是否是缓冲区不足的错误
    if result != 0 && result != ERROR_INSUFFICIENT_BUFFER {
        return Err(ProcessError::NotFound);
    }

    let mut buffer = vec![0u8; buffer_size as usize];

    // 第二次调用获取实际数据
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut c_void,
            &mut buffer_size,
            0, // false
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != 0 {
        return Err(ProcessError::NotFound);
    }

    Ok(buffer)
}

/// 获取扩展 UDP 表
fn get_extended_udp_table(af_inet: u32) -> Result<Vec<u8>, ProcessError> {
    let mut buffer_size: u32 = 0;

    // 第一次调用获取所需缓冲区大小
    let result = unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut buffer_size,
            0, // false
            af_inet,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    // 检查是否是缓冲区不足的错误
    if result != 0 && result != ERROR_INSUFFICIENT_BUFFER {
        return Err(ProcessError::NotFound);
    }

    let mut buffer = vec![0u8; buffer_size as usize];

    // 第二次调用获取实际数据
    let result = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut c_void,
            &mut buffer_size,
            0, // false
            af_inet,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if result != 0 {
        return Err(ProcessError::NotFound);
    }

    Ok(buffer)
}

/// 搜索 IPv4 TCP 连接的 PID
fn search_tcp_v4_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_u32 = u32::from_be_bytes(src_ip.octets()).to_be();

    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_u32 == row.dwLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv6 TCP 连接的 PID
fn search_tcp_v6_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_bytes = src_ip.octets();

    let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID,
            table.dwNumEntries as usize,
        )
    };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_bytes == row.ucLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv4 UDP 连接的 PID
fn search_udp_v4_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_u32 = u32::from_be_bytes(src_ip.octets()).to_be();

    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_u32 == row.dwLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 搜索 IPv6 UDP 连接的 PID
fn search_udp_v6_pid(
    buffer: &[u8],
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
) -> Result<u32, ProcessError> {
    let src_ip_bytes = src_ip.octets();

    let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let table = unsafe { &*table };

    let rows = unsafe {
        std::slice::from_raw_parts(
            table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID,
            table.dwNumEntries as usize,
        )
    };

    for row in rows {
        let port = (row.dwLocalPort as u16).to_be();
        if port == src_port && src_ip_bytes == row.ucLocalAddr {
            return Ok(row.dwOwningPid);
        }
    }

    Err(ProcessError::NotFound)
}

/// 获取进程的可执行文件路径
fn get_process_path(pid: u32) -> Result<String, ProcessError> {
    // let current_pid = unsafe { GetCurrentProcessId() };
    if pid == 0 {
        return Err(ProcessError::NameReadError(format!(
            "Invalid or current process PID: {pid}"
        )));
    }

    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) // 0 means false
    };

    let mut buffer: [u16; 1024] = [0; 1024];
    let len = unsafe {
        GetModuleFileNameExW(
            handle,
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };

    unsafe {
        CloseHandle(handle);
    }

    if len == 0 {
        return Err(ProcessError::NameReadError(format!(
            "Failed to read process name for PID {pid}"
        )));
    }

    // 手动将 UTF-16 转换为 String
    let wide_str: &[u16] = &buffer[..len as usize];
    String::from_utf16(wide_str).map_err(|e| {
        ProcessError::NameReadError(format!("UTF-16 conversion failed for PID {pid}: {e}"))
    })
}

/// 根据进程 ID 获取父进程 ID
pub fn get_ppid(pid: u32) -> Result<u32, ProcessError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(ProcessError::NotFound);
    }

    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

    let ret = unsafe { Process32FirstW(snapshot, &mut entry) };
    if ret == 0 {
        unsafe { CloseHandle(snapshot) };
        return Err(ProcessError::NotFound);
    }

    loop {
        if entry.th32ProcessID == pid {
            unsafe { CloseHandle(snapshot) };
            return Ok(entry.th32ParentProcessID);
        }

        let ret = unsafe { Process32NextW(snapshot, &mut entry) };
        if ret == 0 {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) };
    Err(ProcessError::NotFound)
}
