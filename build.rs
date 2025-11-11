fn main() {
    #[cfg(target_os = "windows")]
    {
        // 链接必要的Windows库
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
    }
}