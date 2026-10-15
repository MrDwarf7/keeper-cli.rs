// Windows release builds embed version metadata; protobuf code is generated on every platform.

use prost::Message;

fn main() {
    // Debug builds don't need the Windows resource toolchain.
    #[cfg(all(windows, not(debug_assertions)))]
    {
        embed_windows_metadata();
    }

    compile_keeper_protos();

    println!("cargo:rerun-if-changed=proto/keeper.fds.bin");
    println!("cargo:rerun-if-changed=build.rs");
}

// The descriptor set is lifted from Commander by tools/extract-protos.ts; compiling it
// directly means no protoc install and field numbers identical to Keeper's own schema.
fn compile_keeper_protos() {
    let fds = prost_types::FileDescriptorSet::decode(&include_bytes!("proto/keeper.fds.bin")[..])
        .expect("proto/keeper.fds.bin is not a valid FileDescriptorSet");
    prost_build::Config::new()
        .include_file("keeper_protos.rs")
        .compile_fds(fds)
        .expect("failed to generate Keeper protobuf code");
}

#[cfg(all(windows, not(debug_assertions)))]
fn embed_windows_metadata() {
    let name = env!("CARGO_PKG_NAME");
    let vers = env!("CARGO_PKG_VERSION");

    let mut res = winresource::WindowsResource::new();
    res.set_language(0x0009);
    res.set("CompanyName", "https://github.com/MrDwarf7");
    res.set("ProductName", name);

    let mut sv: Vec<&str> = vers.split('.').collect();
    while sv.len() < 4 {
        sv.push("0");
    }
    let file_version = format!("{}, {}, {}, {}", sv[0], sv[1], sv[2], sv[3]);
    res.set("FileVersion", file_version.as_str());

    res.compile().expect("Failed to compile Windows version metadata");
}
