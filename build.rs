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
    let fds = prost_types::FileDescriptorSet::decode(include_bytes!("proto/keeper.fds.bin").as_slice())
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

    let mut components = vers.split('.');
    let [major, minor, patch, build] = [
        components
            .next()
            .expect("CARGO_PKG_VERSION is missing its major component")
            .parse::<u16>()
            .expect("CARGO_PKG_VERSION major component is not a valid Windows version number"),
        components
            .next()
            .expect("CARGO_PKG_VERSION is missing its minor component")
            .parse::<u16>()
            .expect("CARGO_PKG_VERSION minor component is not a valid Windows version number"),
        components
            .next()
            .expect("CARGO_PKG_VERSION is missing its patch component")
            .parse::<u16>()
            .expect("CARGO_PKG_VERSION patch component is not a valid Windows version number"),
        components
            .next()
            .unwrap_or("0")
            .parse::<u16>()
            .expect("CARGO_PKG_VERSION build component is not a valid Windows version number"),
    ];
    let file_version = format!("{major}, {minor}, {patch}, {build}");
    res.set("FileVersion", file_version.as_str());

    res.compile().expect("Failed to compile Windows version metadata");
}
