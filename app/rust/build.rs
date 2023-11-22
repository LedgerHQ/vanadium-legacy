extern crate pb_rs;
extern crate walkdir;

use pb_rs::{types::FileDescriptor, ConfigBuilder};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn main() {

    let in_dir = PathBuf::from(::std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("protos");
    // Re-run this build.rs if the protos dir changes (i.e. a new file is added)
    println!("cargo:rerun-if-changed={}", in_dir.to_str().unwrap());

    let out_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = Path::new(&out_dir).join("src/message");
    
    // Find all *.proto files in the `in_dir` and add them to the list of files
    let mut protos = Vec::new();
    let proto_ext = Some(Path::new("proto").as_os_str());
    
    for entry in WalkDir::new(&in_dir) {
        let path = entry.unwrap().into_path();
        if path.extension() == proto_ext {
        // Re-run this build.rs if any of the files in the protos folder change
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
            protos.push(path);
        }
    }

    // Delete all old generated files before re-generating new ones
    if out_dir.exists() {
        std::fs::remove_dir_all(&out_dir).unwrap();
    }
    
    std::fs::DirBuilder::new().create(&out_dir).unwrap();
    let mut config_builder = ConfigBuilder::new(&protos, None, Some(&out_dir), &[in_dir]).unwrap();
    config_builder = config_builder.nostd(true);
    FileDescriptor::run(&config_builder.build()).unwrap();

    // For Python client
    std::process::Command::new("protoc")
        .arg("-I=./protos")
        .arg("--python_out=./client_py")
        .arg("./protos/boiler.proto")
        .output()
        .expect("failed to generate data access classes for Python client");
    
}