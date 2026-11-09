use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let mut include_dirs: Vec<PathBuf> = Vec::new();
    let statik = env::var_os("OPENSSL_STATIC").is_some();

    if let Some(dir) = env::var_os("OPENSSL_DIR") {
        // Manual override: $OPENSSL_DIR/{include,lib}
        let dir = PathBuf::from(dir);
        println!("cargo:rustc-link-search=native={}", dir.join("lib").display());
        let kind = if statik { "static=" } else { "" };
        println!("cargo:rustc-link-lib={kind}ssl");
        println!("cargo:rustc-link-lib={kind}crypto");
        include_dirs.push(dir.join("include"));
    } else {
        // pkg-config emits cargo:rustc-link-* itself. Using its include paths for
        // bindgen keeps headers and linked libs in sync.
        let lib = pkg_config::Config::new()
            .atleast_version("3.0.0")
            .statik(statik)
            .probe("openssl")
            .expect(
                "OpenSSL >= 3.0 not found. Set OPENSSL_DIR, or PKG_CONFIG_PATH \
                 (macOS: $(brew --prefix openssl@3)/lib/pkgconfig)",
            );
        include_dirs.extend(lib.include_paths);
    }

    let mut b = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("(SSL|TLS|DTLS|BIO|X509|X509V3|ERR|PEM|EVP_PKEY|ASN1|GENERAL_NAME|OPENSSL|OpenSSL|CRYPTO|d2i|i2d)_.*")
        .allowlist_type("(SSL|TLS|BIO|X509|EVP_PKEY|ASN1|GENERAL_NAME|OPENSSL|CRYPTO|ossl).*")
        .allowlist_var("(SSL|TLS|TLSEXT|BIO|X509|ERR|OPENSSL|EVP_PKEY|CRYPTO|ASN1|GEN|OSSL)_.*")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .layout_tests(false)
        .generate_comments(false)
        .derive_default(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for d in &include_dirs {
        b = b.clang_arg(format!("-I{}", d.display()));
    }

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    b.generate()
        .expect("bindgen failed")
        .write_to_file(out)
        .expect("write bindings.rs failed");
}
