// Embed Windows exe icon + version metadata at release build time.
// Assets live under assets/ (icon.ico is the Windows resource).
// Non-Windows targets: no-op.

use prost::Message;

fn main() {
    // Release-only on Windows: keep debug builds fast; skip icon tooling.
    #[cfg(all(windows, not(debug_assertions)))]
    {
        embed_windows_icon();
    }

    compile_keeper_protos();

    println!("cargo:rerun-if-changed=assets/icon.ico");
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
fn embed_windows_icon() {
    let name = env!("CARGO_PKG_NAME");
    let vers = env!("CARGO_PKG_VERSION");

    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico").set_language(0x0009); // English
    res.set("CompanyName", "https://github.com/MrDwarf7");
    res.set("ProductName", name);

    let mut sv: Vec<&str> = vers.split('.').collect();
    while sv.len() < 4 {
        sv.push("0");
    }
    let file_version = format!("{}, {}, {}, {}", sv[0], sv[1], sv[2], sv[3]);
    res.set("FileVersion", file_version.as_str());

    res.compile()
        .expect("Failed to compile Windows resources (assets/icon.ico)");
}
