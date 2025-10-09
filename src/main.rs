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

// Simple test function to verify parsing logic
fn test_package_parsing() {
    let test_cases = vec![
        ("hello-world-1.0.0-x86_64.pax", ("hello-world", "1.0.0", Some("x86_64".to_string()))),
        ("simple-package-2.1.0.pax", ("simple-package", "2.1.0", None)),
        ("no-version-arch.pax", ("no-version-arch", "1.0.0", None)),
        ("package-with-many-dashes-1.2.3-x86_64.pax", ("package-with-many-dashes", "1.2.3", Some("x86_64".to_string()))),
    ];

    for (filename, expected) in test_cases {
        println!("Testing: {}", filename);
        let filename_without_ext = filename.strip_suffix(".pax").unwrap_or(filename);
        let parts: Vec<&str> = filename_without_ext.split('-').collect();

        if parts.len() >= 2 {
            // Check if the last part is a known architecture
            let (architecture, remaining_parts) = if parts.len() >= 3 {
                match parts[parts.len() - 1] {
                    "x86_64" | "aarch64" | "arm64" => {
                        (Some(parts[parts.len() - 1].to_string()), &parts[..parts.len() - 1])
                    }
                    _ => (None, parts.as_slice())
                }
            } else {
                (None, parts.as_slice())
            };

            // For the remaining parts, identify version vs name
            let (pkg_name, pkg_version) = if remaining_parts.len() >= 2 {
                // Check if the last remaining part looks like a version
                let last_part = remaining_parts[remaining_parts.len() - 1];
                let is_version_like = last_part.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && last_part.contains('.')
                    && !last_part.starts_with('.') && !last_part.ends_with('.');

                if is_version_like {
                    // Last part is version, everything before is name
                    let name_parts: Vec<&str> = remaining_parts[..remaining_parts.len() - 1].to_vec();
                    let pkg_name = name_parts.join("-");
                    (pkg_name, last_part.to_string())
                } else {
                    // Last part is part of name, join all as name and use default version
                    let pkg_name = remaining_parts.join("-");
                    (pkg_name, "1.0.0".to_string())
                }
            } else {
                // Only one part, use it as name with default version
                (remaining_parts[0].to_string(), "1.0.0".to_string())
            };

            println!("  Result: name='{}', version='{}', arch='{:?}'", pkg_name, pkg_version, architecture);
            println!("  Expected: name='{}', version='{}', arch='{:?}'",
                     expected.0, expected.1, expected.2);

            assert_eq!(pkg_name, expected.0);
            assert_eq!(pkg_version, expected.1);
            assert_eq!(architecture, expected.2);
            println!("  ✓ PASS");
        }
        println!();
    }
}

// Helper function to calculate file hash (simple implementation)
fn calculate_hash(path: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn scan_packages_directory(directory: &Path) -> Result<MultiDistroRepository, Box<dyn std::error::Error>> {
    let mut distros = Vec::new();

    // Scan for subdirectories in the packages directory (each represents a distro)
    eprintln!("Scanning packages directory: {:?}", directory);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        eprintln!("Found entry: {:?}", path);

        if path.is_dir() {
            eprintln!("Entry is a directory: {:?}", path);
            if let Some(distro_name) = path.file_name().and_then(|n| n.to_str()) {
                eprintln!("Distro name: {}", distro_name);
                // Scan for .pax files in this distro directory
                let mut packages = Vec::new();

                for package_entry in fs::read_dir(&path)? {
                    let package_entry = package_entry?;
                    let package_path = package_entry.path();
                    eprintln!("Found package entry: {:?}", package_path);

                    if package_path.is_file() {
                        eprintln!("Package entry is a file: {:?}", package_path);
                        if let Some(file_name) = package_path.file_name().and_then(|n| n.to_str()) {
                            eprintln!("Package file name: {}", file_name);
                            if file_name.ends_with(".pax") {
                                eprintln!("File ends with .pax, processing: {}", file_name);
                                let file_size = fs::metadata(&package_path)?.len();

                                // Parse package information from filename
                                // Expected format: name-version-arch.pax or name-version.pax
                                let filename_without_ext = file_name.strip_suffix(".pax").unwrap_or(file_name);

                                // Split by '-' to get components
                                let parts: Vec<&str> = filename_without_ext.split('-').collect();

                                if parts.len() >= 2 {
                                    // Check if the last part is a known architecture
                                    let (architecture, remaining_parts) = if parts.len() >= 3 {
                                        match parts[parts.len() - 1] {
                                            "x86_64" | "aarch64" | "arm64" => {
                                                (Some(parts[parts.len() - 1].to_string()), &parts[..parts.len() - 1])
                                            }
                                            _ => (None, parts.as_slice())
                                        }
                                    } else {
                                        (None, parts.as_slice())
                                    };

                                    // For the remaining parts, identify version vs name
                                    // The version is typically the last component that looks like semantic versioning
                                    let (pkg_name, pkg_version) = if remaining_parts.len() >= 2 {
                                        // Check if the last remaining part looks like a version
                                        let last_part = remaining_parts[remaining_parts.len() - 1];
                                        let is_version_like = last_part.chars().all(|c| c.is_ascii_digit() || c == '.')
                                            && last_part.contains('.')
                                            && !last_part.starts_with('.') && !last_part.ends_with('.');

                                        if is_version_like {
                                            // Last part is version, everything before is name
                                            let name_parts: Vec<&str> = remaining_parts[..remaining_parts.len() - 1].to_vec();
                                            let pkg_name = name_parts.join("-");
                                            (pkg_name, last_part.to_string())
                                        } else {
                                            // Last part is part of name, join all as name and use default version
                                            let pkg_name = remaining_parts.join("-");
                                            (pkg_name, "1.0.0".to_string())
                                        }
                                    } else {
                                        // Only one part, use it as name with default version
                                        (remaining_parts[0].to_string(), "1.0.0".to_string())
                                    };

                                    packages.push(PackageEntry {
                                        name: pkg_name.clone(),
                                        version: pkg_version.clone(),
                                        architecture,
                                        description: format!("Package {} version {}", pkg_name, pkg_version),
                                        dependencies: Vec::new(),
                                        runtime_dependencies: Vec::new(),
                                        provides: Vec::new(),
                                        hash: calculate_hash(&package_path),
                                        size: file_size,
                                        download_url: format!("/packages/{}/{}", distro_name, file_name),
                                        signature_url: format!("/packages/{}/{}.sig", distro_name, file_name),
                                    });
                                }
                            }
                        }
                    }
                }

                // Generate metadata for this distro if it has packages
                if !packages.is_empty() {
                    let last_updated = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    distros.push(DistroRepository {
                        name: distro_name.to_string(),
                        packages,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        last_updated,
                    });
                }
            }
        }
    }

    Ok(MultiDistroRepository { distros })
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
        Ok(multi_distro) => {
            match serde_json::to_string(&multi_distro) {
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

#[get("/repository/{distro}/metadata")]
async fn distro_metadata(
    distro: web::Path<String>,
    data: web::Data<CoreData>,
) -> Result<HttpResponse, actix_web::Error> {
    let distro_name = distro.into_inner();
    match scan_packages_directory(&data.directory) {
        Ok(multi_distro) => {
            // Find the specific distro
            for distro_repo in &multi_distro.distros {
                if distro_repo.name == distro_name {
                    let index = RepositoryIndex {
                        packages: distro_repo.packages.clone(),
                        version: distro_repo.version.clone(),
                        last_updated: distro_repo.last_updated,
                    };
                    match serde_json::to_string(&index) {
                        Ok(body) => return Ok(HttpResponse::with_body(StatusCode::OK, BoxBody::new(body))),
                        Err(_) => return Err(InternalError::new(
                            "Error serializing repository index!",
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ).into()),
                    }
                }
            }
            Err(InternalError::new(
                "Distro not found!",
                StatusCode::NOT_FOUND,
            ).into())
        }
        Err(_) => Err(InternalError::new(
            "Error scanning packages directory!",
            StatusCode::INTERNAL_SERVER_ERROR,
        ).into()),
    }
}

#[get("/packages/{distro}/{filename:.*}")]
async fn serve_package(
    path: web::Path<(String, String)>,
    data: web::Data<CoreData>,
) -> Result<NamedFile, actix_web::Error> {
    let (distro, filename) = path.into_inner();
    let file_path = format!("{}/{}", distro, filename);

    // Security check - ensure the file is within the packages directory
    if let Some(safe_path) = path_check(&file_path, &data.directory) {
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

fn main() {
    // Test the parsing logic first
    test_package_parsing();
    println!("All parsing tests passed!");

    // Then run the server
    println!("Starting server...");
    server_main().unwrap();
}

#[actix_web::main]
async fn server_main() -> std::io::Result<()> {
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
            .service(distro_metadata)
            .service(serve_package)
            .service(version)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

// Repository index structures for package manager compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDistroRepository {
    pub distros: Vec<DistroRepository>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroRepository {
    pub name: String,
    pub packages: Vec<PackageEntry>,
    pub version: String,
    pub last_updated: i64,
}

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
