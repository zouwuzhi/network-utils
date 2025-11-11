use network_utils::process;
use std::process as std_process;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取当前进程的 PID
    let current_pid = std_process::id();
    println!("Current process PID: {}", current_pid);

    let instant = Instant::now();
    // 测试获取当前进程的父进程 PID
    match process::get_ppid(current_pid) {
        #[cfg(target_os = "macos")]
        Some(ppid) => println!("Parent process PID: {}", ppid),
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
        Ok(ppid) => println!("Parent process PID: {}", ppid),
        #[cfg(target_os = "macos")]
        None => println!("Failed to get parent PID"),
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
        Err(e) => println!("Failed to get parent PID: {}", e),
    }
    println!("Elapsed time: {:?}", instant.elapsed());
    let instant = Instant::now();
    // 测试获取一个不存在的进程 PID（应该返回错误）
    match process::get_ppid(999999) {
        #[cfg(target_os = "macos")]
        Some(ppid) => println!("Non-existing process parent PID: {}", ppid),
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
        Ok(ppid) => println!("Non-existing process parent PID: {}", ppid),
        #[cfg(target_os = "macos")]
        None => println!("Expected None for non-existing process"),
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
        Err(e) => println!("Expected error for non-existing process: {}", e),
    }
    println!("Elapsed time: {:?}", instant.elapsed());
    Ok(())
}
