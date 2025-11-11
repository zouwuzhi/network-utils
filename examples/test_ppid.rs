use network_utils::process;
use std::process as std_process;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取当前进程的 PID
    let current_pid = std_process::id();
    println!("Current process PID: {}", current_pid);

    // 测试获取当前进程的父进程 PID
    match process::get_ppid(current_pid) {
        Ok(ppid) => println!("Parent process PID: {}", ppid),
        Err(e) => println!("Failed to get parent PID: {}", e),
    }

    // 测试获取一个不存在的进程 PID（应该返回错误）
    match process::get_ppid(999999) {
        Ok(ppid) => println!("Non-existing process parent PID: {}", ppid),
        Err(e) => println!("Expected error for non-existing process: {}", e),
    }

    Ok(())
}
