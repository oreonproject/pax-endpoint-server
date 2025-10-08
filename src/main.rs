use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use actix_files::NamedFile;
use actix_web::{
    App, HttpResponse, HttpServer, body::BoxBody, error::InternalError, get, http::StatusCode, web,
};
use serde::{Deserialize, Serialize};

// Helper function to calculate file hash (simple implementation)
fn calculate_hash(path: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn scan_packages_directory(directory: &Path) -> Result<RepositoryIndex, Box<dyn std::error::Error>> {
    let mut packages = Vec::new();

    // Scan for .pax files directly in the packages directory
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.ends_with(".pax") {
                    let file_size = fs::metadata(&path)?.len();

                    // Parse package information from filename
                    // Expected format: name-version-arch.pax or name-version.pax
                    let filename_without_ext = file_name.strip_suffix(".pax").unwrap_or(file_name);

                    // Split by '-' to get components
                    let parts: Vec<&str> = filename_without_ext.split('-').collect();

                    if parts.len() >= 2 {
                        let pkg_name = parts[0];
                        let pkg_version = parts[1];
                        let architecture = if parts.len() >= 3 {
                            match parts[2] {
                                "x86_64" | "aarch64" | "arm64" => Some(parts[2].to_string()),
                                _ => None,
                            }
                        } else {
                            None
                        };

                        packages.push(PackageEntry {
                            name: pkg_name.to_string(),
                            version: pkg_version.to_string(),
                            architecture,
                            description: format!("Package {} version {}", pkg_name, pkg_version),
                            dependencies: Vec::new(),
                            runtime_dependencies: Vec::new(),
                            provides: Vec::new(),
                            hash: calculate_hash(&path),
                            size: file_size,
                            download_url: format!("/packages/{}", file_name),
                            signature_url: format!("/packages/{}.sig", file_name),
                        });
                    }
                }
            }
        }
    }

    let last_updated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Ok(RepositoryIndex {
        packages,
        version: env!("CARGO_PKG_VERSION").to_string(),
        last_updated,
    })
}

fn yaml_file_to_package_metadata(path: &PathBuf) -> Option<PackageMetadata> {
    let mut file = fs::File::open(path).ok()?;
    let mut data = String::new();
    file.read_to_string(&mut data).ok()?;
    serde_yml::from_str(&data).ok()
}

#[get("/repository/metadata")]
async fn repository_metadata(
    data: web::Data<CoreData>,
) -> Result<HttpResponse, actix_web::Error> {
    match scan_packages_directory(&data.directory) {
        Ok(index) => {
            match serde_json::to_string(&index) {
                Ok(body) => Ok(HttpResponse::with_body(StatusCode::OK, BoxBody::new(body))),
                Err(_) => Err(InternalError::new(
                    "Error serializing repository index!",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ).into()),
            }
        }
        Err(_) => Err(InternalError::new(
            "Error scanning packages directory!",
            StatusCode::INTERNAL_SERVER_ERROR,
        ).into()),
    }
}

#[get("/packages/{filename:.*}")]
async fn serve_package(
    filename: web::Path<String>,
    data: web::Data<CoreData>,
) -> Result<NamedFile, actix_web::Error> {
    let filename = filename.into_inner();

    // Security check - ensure the file is within the packages directory
    if let Some(safe_path) = path_check(&filename, &data.directory) {
        match actix_files::NamedFile::open(safe_path) {
            Ok(file) => Ok(file),
            Err(_) => Err(InternalError::new(
                "Package file not found.",
                StatusCode::NOT_FOUND,
            ).into()),
        }
    } else {
        Err(InternalError::new(
            "Access denied.",
            StatusCode::FORBIDDEN,
        ).into())
    }
}


fn yaml_file_to_json_str(path: &PathBuf) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut data = String::new();
    file.read_to_string(&mut data).ok()?;
    let body: PackageMetadata = serde_yml::from_str(&data).ok()?;
    serde_json::to_string(&body).ok()
}

#[get("/version")]
async fn version() -> Result<HttpResponse, actix_web::Error> {
    Ok(HttpResponse::with_body(
        StatusCode::OK,
        BoxBody::new(env!("CARGO_PKG_VERSION")),
    ))
}

#[derive(Clone)]
struct CoreData {
    directory: PathBuf,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut directory = std::env::current_dir()?;
    let mut port = 8080u16;
    let args = std::env::args().collect::<Vec<String>>();
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if let Some(arg) = arg.strip_prefix("--") {
            match arg {
                "directory" => {
                    if let Some(loc) = args.next() {
                        directory = PathBuf::from(loc)
                    }
                }
                "port" => {
                    if let Some(Ok(val)) = args.next().map(|x| x.parse::<u16>()) {
                        port = val
                    }
                }
                _ => panic!("Unknown long-flag {arg}!"),
            }
        } else if let Some(arg) = arg.strip_prefix("-") {
            for arg in arg.chars() {
                match arg {
                    'd' => {
                        if let Some(loc) = args.next() {
                            directory = PathBuf::from(loc)
                        }
                    }
                    'p' => {
                        if let Some(Ok(val)) = args.next().map(|x| x.parse::<u16>()) {
                            port = val
                        }
                    }
                    _ => panic!("Unknown short-flag {arg}!"),
                }
            }
        } else {
            panic!("Unknown parameter {arg}!");
        }
    }
    println!("Using folder {}", directory.display());
    println!("Using port {port}");
    let data = CoreData { directory };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(data.clone()))
            .service(repository_metadata)
            .service(serve_package)
            .service(version)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

// Repository index structures for package manager compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndex {
    pub packages: Vec<PackageEntry>,
    pub version: String,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub description: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub runtime_dependencies: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    pub hash: String,
    pub size: u64,
    pub download_url: String,
    pub signature_url: String,
}

// Detailed package metadata (from API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub origin: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub runtime_dependencies: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    pub build: Option<String>,
    pub install: Option<String>,
    pub uninstall: Option<String>,
    pub hash: String,
    pub binary: Option<String>,
}

fn path_check(subpath_str: &str, origpath: &Path) -> Option<PathBuf> {
    /*
    The following code is not my own, but adapted slightly to match my use-case.

    Project Title: tower-rs/tower-http
    Snippet Title: build_and_validate_path
    Author(s): carllerche and github:tower-rs:publish
    Date: 03/Jun/2025
    Date Accessed: 10/Aug/2025 01:30AM AEST
    Code version: 0.6.6
    Type: Source Code
    Availability: https://docs.rs/tower-http/latest/src/tower_http/services/fs/serve_dir/mod.rs.html#458-483
    Licence: MIT (docs.rs) / None (github.com)
     */
    let mut finalpath = origpath.to_path_buf();
    let subpath = subpath_str.trim_start_matches('/');
    let subpath = Path::new(subpath);
    for component in subpath.components() {
        match component {
            Component::Normal(comp) => {
                if Path::new(&comp)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
                {
                    finalpath.push(comp)
                } else {
                    return None;
                }
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return None;
            }
        }
    }
    Some(finalpath)
}
