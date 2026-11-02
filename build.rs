use std::path::PathBuf;

fn main() {
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo must provide the target architecture");
    let simd_src_file = if target_arch == "x86_64" {
        "phc-winner-argon2-20190702/src/opt.c"
    } else {
        "phc-winner-argon2-20190702/src/ref.c"
    };

    let src = [
        "phc-winner-argon2-20190702/src/argon2.c",
        "phc-winner-argon2-20190702/src/core.c",
        "phc-winner-argon2-20190702/src/blake2/blake2b.c",
        "phc-winner-argon2-20190702/src/thread.c",
        "phc-winner-argon2-20190702/src/encoding.c",
        simd_src_file,
    ];

    let mut builder = cc::Build::new();

    let mut build = builder
        .files(src.iter())
        .opt_level(3) // Optimize even in debug mode to prevent excessive slowness
        .include("phc-winner-argon2-20190702/include")
        .warnings(false)
        .flag("-std=c89")
        .flag("-pthread");

    println!("cargo:rerun-if-env-changed=ARGON2_KDF_C_COMPILER_FLAGS");
    if let Ok(compiler_flags) = std::env::var("ARGON2_KDF_C_COMPILER_FLAGS") {
        for flag in compiler_flags.split(';') {
            build = build.flag(flag);
        }
    }

    build.compile("argon2");

    println!("cargo:rerun-if-changed=argon2_bindings.h");

    bindgen::Builder::default()
        .header("argon2_bindings.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings for argon2 library");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let bindings = bindgen::Builder::default()
        .header("argon2_bindings.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings for argon2 library");

    let bindings_out_path = PathBuf::from(format!("{out_dir}/argon2_bindings.rs"));

    bindings
        .write_to_file(bindings_out_path)
        .expect("Couldn't write argon2 library bindings");
}
