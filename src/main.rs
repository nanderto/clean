use std::path::PathBuf;
use std::fs;
use clap::Parser;
use walkdir::WalkDir;
use anyhow::{Result, Context};
use rayon::prelude::*;
use colored::*;

/// Program to find and optionally delete empty directories
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to start searching from
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Delete empty folders if set
    #[arg(short, long)]
    delete: bool,

    /// Show detailed information about directories
    #[arg(short, long)]
    verbose: bool,

    /// Only delete directories known to be safe (cache, temp, etc.)
    #[arg(short, long)]
    safe: bool,

    /// Force deletion by taking ownership and modifying permissions
    #[arg(short, long)]
    force: bool,

    /// Recursively delete non-empty directories if deletion fails (DANGEROUS)
    #[arg(long, help = "Allow deletion of system and hidden directories (DANGEROUS)")]
    delete_system_hidden: bool,

    /// Run deletion in parallel (experimental)
    #[arg(short = 'p', long, help = "Delete empty directories in parallel (experimental)")]
    parallel: bool,
}

fn is_system_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    // Only match exact Windows system directories
    path_str.contains("\\c:\\windows\\") ||
    path_str.contains("\\c:\\program files\\") ||
    path_str.contains("\\c:\\program files (x86)\\") ||
    path_str.contains("\\c:\\system32\\") ||
    path_str.contains("\\c:\\syswow64\\")
}

fn is_appdata_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\appdata\\")
}

fn is_cache_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\cache\\") ||
    path_str.contains("\\temp\\") ||
    path_str.contains("\\transient\\") ||
    path_str.contains("\\temporary\\") ||
    path_str.contains("\\solutioncaches\\") ||
    path_str.contains("\\tiles\\") ||
    path_str.contains("\\compile-cache\\") 
}

fn is_jetbrains_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\jetbrains\\") ||
    path_str.contains("\\resharper\\") ||
    path_str.contains("\\dotfiles\\") ||
    path_str.contains("\\externalannotations\\")
}

fn is_chrome_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\google\\chrome\\") ||
    path_str.contains("\\chrome cleanup tool\\") ||
    path_str.contains("\\software reporter tool\\") ||
    path_str.contains("\\crashreports\\")
}

fn is_goto_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\goto meeting\\") ||
    path_str.contains("\\goto opener\\")
}

fn is_isolated_storage_directory(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("\\isolatedstorage\\")
}

fn get_directory_type(path: &PathBuf) -> &'static str {
    if is_system_directory(path) {
        "System"
    } else if is_chrome_directory(path) {
        "Chrome"
    } else if is_goto_directory(path) {
        "GoTo"
    } else if is_isolated_storage_directory(path) {
        "IsolatedStorage"
    } else if is_jetbrains_directory(path) {
        "JetBrains"
    } else if is_cache_directory(path) {
        "Cache"
    } else if is_appdata_directory(path) {
        "AppData"
    } else {
        "User"
    }
}

fn get_directory_description(dir_type: &str) -> &'static str {
    match dir_type {
        "System" => "This might be a system directory. Please verify before deleting.",
        "Chrome" => "This is a Google Chrome cache or temporary directory that can be safely deleted.",
        "GoTo" => "This is a GoToMeeting/GoTo Opener temporary directory that can be safely deleted.",
        "IsolatedStorage" => "This is a .NET IsolatedStorage directory that can be safely deleted.",
        "JetBrains" => "This is a JetBrains IDE cache/annotation directory that can be safely deleted.",
        "Cache" => "This is a temporary cache directory that can be safely deleted.",
        "AppData" => "This is likely a temporary or cache directory that can be safely deleted.",
        _ => "This is a regular directory.",
    }
}

fn inspect_directory(path: &PathBuf) -> Result<()> {
    let read_dir = fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?;
    
    println!("\nInspecting directory: {}", path.display());
    println!("Contents:");
    
    let mut has_entries = false;
    for entry in read_dir {
        let entry = entry.with_context(|| format!("Failed to read directory entry in: {}", path.display()))?;
        has_entries = true;
        
        let file_type = entry.file_type()
            .map(|t| if t.is_dir() { "Directory" } else { "File" })
            .unwrap_or("Unknown");
            
        println!("  - {} ({})", entry.file_name().to_string_lossy(), file_type);
    }
    
    if !has_entries {
        println!("  No entries found (except . and ..)");
    }
    
    Ok(())
}

fn is_dir_empty(path: &PathBuf) -> Result<bool> {
    let read_dir = fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?;
    
    let mut has_entries = false;
    
    // Check if there are any entries (including hidden files)
    for entry in read_dir {
        let entry = entry.with_context(|| format!("Failed to read directory entry in: {}", path.display()))?;
        
        // Skip . and .. entries
        let file_name = entry.file_name();
        if file_name == "." || file_name == ".." {
            continue;
        }
        
        has_entries = true;
        
        // Check if the entry is a file or directory
        let file_type = entry.file_type()
            .with_context(|| format!("Failed to get file type for: {}", entry.path().display()))?;
        
        // If it's a file, the directory is not empty
        if file_type.is_file() {
            return Ok(false);
        }
        
        // If it's a directory, check if it's empty recursively
        if file_type.is_dir() {
            if !is_dir_empty(&entry.path())? {
                return Ok(false);
            }
        }
    }
    
    // If we get here, either there were no entries or all entries were empty directories
    Ok(!has_entries)
}

fn is_safe_directory(dir_type: &str) -> bool {
    match dir_type {
        "Chrome" | "GoTo" | "IsolatedStorage" | "JetBrains" | "Cache" | "AppData" => true,
        _ => false,
    }
}

fn find_empty_dirs(path: &PathBuf, verbose: bool, safe_only: bool) -> Result<Vec<PathBuf>> {
    // Collect all directories first, including hidden ones
    let dirs: Vec<PathBuf> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();

    // Process directories in parallel
    let empty_dirs: Vec<PathBuf> = dirs.par_iter()
        .filter_map(|dir_path| {
            match is_dir_empty(dir_path) {
                Ok(true) => {
                    let dir_type = get_directory_type(dir_path);
                    
                    // Skip non-safe directories if safe_only is true
                    if safe_only && !is_safe_directory(dir_type) {
                        return None;
                    }
                    
                    // Print information about the empty directory
                    let description = get_directory_description(dir_type);
                    match dir_type {
                        "System" => {
                            println!("WARNING: Found empty system directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "Chrome" => {
                            println!("Found empty Chrome directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "GoTo" => {
                            println!("Found empty GoTo directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "IsolatedStorage" => {
                            println!("Found empty IsolatedStorage directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "JetBrains" => {
                            println!("Found empty JetBrains directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "Cache" => {
                            println!("Found empty cache directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        "AppData" => {
                            println!("Found empty AppData directory: {}", dir_path.display());
                            println!("  {}", description);
                        }
                        _ => {
                            println!("Found empty directory: {}", dir_path.display());
                            // Do not print description for regular directories
                        }
                    }
                    
                    // Handle verbose output if requested
                    if verbose {
                        if let Err(e) = inspect_directory(dir_path) {
                            eprintln!("Error inspecting directory: {}", e);
                        }
                    }
                    
                    Some(dir_path.clone())
                }
                Ok(false) => None,
                Err(e) => {
                    eprintln!("Error checking directory {}: {}", dir_path.display(), e);
                    None
                }
            }
        })
        .collect();
    
    Ok(empty_dirs)
}

fn take_ownership_and_grant_permissions(path: &PathBuf) -> Result<()> {
    let path_str = path.to_string_lossy();
    
    // Take ownership
    let take_ownership = std::process::Command::new("icacls")
        .args([&path_str, "/setowner", "Administrators", "/T", "/C"])
        .output()?;
    
    if !take_ownership.status.success() {
        return Err(anyhow::anyhow!("Failed to take ownership: {}", String::from_utf8_lossy(&take_ownership.stderr)));
    }
    
    // Grant full control
    let grant_permissions = std::process::Command::new("icacls")
        .args([&path_str, "/grant", "Administrators:(OI)(CI)F", "/T"])
        .output()?;
    
    if !grant_permissions.status.success() {
        return Err(anyhow::anyhow!("Failed to grant permissions: {}", String::from_utf8_lossy(&grant_permissions.stderr)));
    }
    
    Ok(())
}

fn recursive_delete_empty_dirs(path: &PathBuf, safe_only: bool, force: bool, verbose: bool, delete_system_hidden: bool) -> Result<(usize, usize, usize, Vec<PathBuf>)> {
    let mut deleted_count = 0;
    let mut skipped_count = 0;
    let mut error_count = 0;
    let mut failed_dirs = Vec::new();

    // First, recursively process all subdirectories
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries {
            if let Ok(entry) = entry {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Ok((sub_deleted, sub_skipped, sub_errors, sub_failed)) = 
                        recursive_delete_empty_dirs(&entry.path(), safe_only, force, verbose, delete_system_hidden) {
                        deleted_count += sub_deleted;
                        skipped_count += sub_skipped;
                        error_count += sub_errors;
                        failed_dirs.extend(sub_failed);
                    }
                }
            }
        }
    }

    // Now check if this directory is empty
    if is_dir_empty(path)? {
        let dir_type = get_directory_type(path);
        let is_hidden = is_hidden_directory(path);
        #[cfg(windows)]
        {
            let sys_files = list_system_files(path, true);
            let hidden_files = list_hidden_files(path, true);
            if (!delete_system_hidden) && (!sys_files.is_empty() || !hidden_files.is_empty()) {
                println!("\nWARNING: Directory contains system or hidden files and will not be deleted: {}", path.display());
                if !sys_files.is_empty() {
                    println!("  System files present:");
                    for f in &sys_files {
                        println!("    * {}", f.display());
                    }
                }
                if !hidden_files.is_empty() {
                    println!("  Hidden files present:");
                    for f in &hidden_files {
                        println!("    * {}", f.display());
                    }
                }
                println!("  Use --delete-system-hidden to allow deletion of such directories.\n");
                skipped_count += 1;
                return Ok((deleted_count, skipped_count, error_count, failed_dirs));
            }
        }
        if verbose {
            println!("\nChecking directory: {}", path.display());
            println!("  Directory type: {}", dir_type);
            println!("  Safe only mode: {}", safe_only);
            println!("  Is safe directory: {}", is_safe_directory(dir_type));
            println!("  Is hidden directory: {}", is_hidden);
        }
        // Skip non-safe directories if safe_only is true
        if safe_only && !is_safe_directory(dir_type) {
            if verbose {
                println!("  Skipping non-safe directory");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }
        // Skip system and hidden directories unless delete_system_hidden is set
        if (is_protected_directory(dir_type) || is_hidden) && !delete_system_hidden {
            if verbose {
                println!("  Skipping system or hidden directory (use --delete-system-hidden to allow)");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }

        // Print information about the empty directory
        let _description = get_directory_description(dir_type);
        let dir_label = match dir_type {
            "Chrome" | "GoTo" | "IsolatedStorage" | "JetBrains" | "Cache" | "AppData" => {
                format!("{} directory: {}", dir_type, path.display())
            }
            _ => {
                format!("directory: {}", path.display())
            }
        };
        // Try to delete the directory
        match fs::remove_dir(path) {
            Ok(_) => {
                println!("Deleted {} ✓", dir_label);
                deleted_count += 1;
            }
            Err(e) => {
                if force {
                    print!("Deleting {}... ", dir_label);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    print!("{}", "Permission denied, attempting to force delete...".yellow());
                    match take_ownership_and_grant_permissions(path) {
                        Ok(_) => {
                            match fs::remove_dir(path) {
                                Ok(_) => {
                                    println!("Deleted {} ✓", dir_label);
                                    deleted_count += 1;
                                }
                                Err(e) => {
                                    println!("✗");
                                    eprintln!("{}", format!("Failed to force delete {}: {}", path.display(), e).red());
                                    error_count += 1;
                                    if path.exists() {
                                        failed_dirs.push(path.clone());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("✗");
                            eprintln!("{}", format!("Failed to take ownership of {}: {}", path.display(), e).red());
                            error_count += 1;
                            if path.exists() {
                                failed_dirs.push(path.clone());
                            }
                        }
                    }
                } else {
                    print!("Deleting {}... ", dir_label);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    println!("✗");
                    eprintln!("{}", format!("Failed to delete {}: {}", path.display(), e).red());
                    error_count += 1;
                    if path.exists() {
                        failed_dirs.push(path.clone());
                    }
                }
            }
        }
    } else if delete_system_hidden {
        let dir_type = get_directory_type(path);
        if verbose {
            println!("\nRecursively deleting non-empty directory: {}", path.display());
            println!("  Directory type: {}", dir_type);
        }
        // Skip system directories
        if dir_type == "System" {
            if verbose {
                println!("  Skipping system directory");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }
        #[cfg(windows)]
        {
            if is_reparse_point(path) {
                println!("WARNING: Directory is a reparse point (junction, symlink, or mount point): {}", path.display());
            }
            if let Err(e) = clear_attributes_recursive(path) {
                println!("Failed to clear attributes for {}: {}", path.display(), e);
            }
        }
        match fs::remove_dir_all(path) {
            Ok(_) => {
                println!("Recursively deleted: {}", path.display());
                deleted_count += 1;
            }
            Err(e) => {
                println!("Failed to recursively delete {}: {}", path.display(), e);
                error_count += 1;
                if path.exists() {
                    failed_dirs.push(path.clone());
                }
            }
        }
    }
    Ok((deleted_count, skipped_count, error_count, failed_dirs))
}

fn recursive_delete_empty_dirs_parallel(path: &PathBuf, safe_only: bool, force: bool, verbose: bool, delete_system_hidden: bool) -> Result<(usize, usize, usize, Vec<PathBuf>)> {
    let mut deleted_count = 0;
    let mut skipped_count = 0;
    let mut error_count = 0;
    let mut failed_dirs = Vec::new();

    // Collect subdirectories first
    let subdirs: Vec<PathBuf> = match fs::read_dir(path) {
        Ok(entries) => entries.filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    Some(e.path())
                } else {
                    None
                }
            })
        }).collect(),
        Err(_) => Vec::new(),
    };

    // Process subdirectories in parallel
    let results: Vec<_> = subdirs.par_iter().map(|subdir| {
        recursive_delete_empty_dirs_parallel(subdir, safe_only, force, verbose, delete_system_hidden)
    }).collect();

    for res in results {
        if let Ok((sub_deleted, sub_skipped, sub_errors, sub_failed)) = res {
            deleted_count += sub_deleted;
            skipped_count += sub_skipped;
            error_count += sub_errors;
            failed_dirs.extend(sub_failed);
        }
    }

    // Now check if this directory is empty (same as original)
    if is_dir_empty(path)? {
        let dir_type = get_directory_type(path);
        let is_hidden = is_hidden_directory(path);
        #[cfg(windows)]
        {
            let sys_files = list_system_files(path, true);
            let hidden_files = list_hidden_files(path, true);
            if (!delete_system_hidden) && (!sys_files.is_empty() || !hidden_files.is_empty()) {
                println!("\nWARNING: Directory contains system or hidden files and will not be deleted: {}", path.display());
                if !sys_files.is_empty() {
                    println!("  System files present:");
                    for f in &sys_files {
                        println!("    * {}", f.display());
                    }
                }
                if !hidden_files.is_empty() {
                    println!("  Hidden files present:");
                    for f in &hidden_files {
                        println!("    * {}", f.display());
                    }
                }
                println!("  Use --delete-system-hidden to allow deletion of such directories.\n");
                skipped_count += 1;
                return Ok((deleted_count, skipped_count, error_count, failed_dirs));
            }
        }
        if verbose {
            println!("\nChecking directory: {}", path.display());
            println!("  Directory type: {}", dir_type);
            println!("  Safe only mode: {}", safe_only);
            println!("  Is safe directory: {}", is_safe_directory(dir_type));
            println!("  Is hidden directory: {}", is_hidden);
        }
        if safe_only && !is_safe_directory(dir_type) {
            if verbose {
                println!("  Skipping non-safe directory");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }
        if (is_protected_directory(dir_type) || is_hidden) && !delete_system_hidden {
            if verbose {
                println!("  Skipping system or hidden directory (use --delete-system-hidden to allow)");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }
        let _description = get_directory_description(dir_type);
        let dir_label = match dir_type {
            "Chrome" | "GoTo" | "IsolatedStorage" | "JetBrains" | "Cache" | "AppData" => {
                format!("{} directory: {}", dir_type, path.display())
            }
            _ => {
                format!("directory: {}", path.display())
            }
        };
        match fs::remove_dir(path) {
            Ok(_) => {
                println!("Deleted {} ✓", dir_label);
                deleted_count += 1;
            }
            Err(e) => {
                if force {
                    print!("Deleting {}... ", dir_label);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    print!("{}", "Permission denied, attempting to force delete...".yellow());
                    match take_ownership_and_grant_permissions(path) {
                        Ok(_) => {
                            match fs::remove_dir(path) {
                                Ok(_) => {
                                    println!("Deleted {} ✓", dir_label);
                                    deleted_count += 1;
                                }
                                Err(e) => {
                                    println!("✗");
                                    eprintln!("{}", format!("Failed to force delete {}: {}", path.display(), e).red());
                                    error_count += 1;
                                    if path.exists() {
                                        failed_dirs.push(path.clone());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("✗");
                            eprintln!("{}", format!("Failed to take ownership of {}: {}", path.display(), e).red());
                            error_count += 1;
                            if path.exists() {
                                failed_dirs.push(path.clone());
                            }
                        }
                    }
                } else {
                    print!("Deleting {}... ", dir_label);
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    println!("✗");
                    eprintln!("{}", format!("Failed to delete {}: {}", path.display(), e).red());
                    error_count += 1;
                    if path.exists() {
                        failed_dirs.push(path.clone());
                    }
                }
            }
        }
    } else if delete_system_hidden {
        let dir_type = get_directory_type(path);
        if verbose {
            println!("\nRecursively deleting non-empty directory: {}", path.display());
            println!("  Directory type: {}", dir_type);
        }
        if dir_type == "System" {
            if verbose {
                println!("  Skipping system directory");
            }
            skipped_count += 1;
            return Ok((deleted_count, skipped_count, error_count, failed_dirs));
        }
        #[cfg(windows)]
        {
            if is_reparse_point(path) {
                println!("WARNING: Directory is a reparse point (junction, symlink, or mount point): {}", path.display());
            }
            if let Err(e) = clear_attributes_recursive(path) {
                println!("Failed to clear attributes for {}: {}", path.display(), e);
            }
        }
        match fs::remove_dir_all(path) {
            Ok(_) => {
                println!("Recursively deleted: {}", path.display());
                deleted_count += 1;
            }
            Err(e) => {
                println!("Failed to recursively delete {}: {}", path.display(), e);
                error_count += 1;
                if path.exists() {
                    failed_dirs.push(path.clone());
                }
            }
        }
    }
    Ok((deleted_count, skipped_count, error_count, failed_dirs))
}

#[cfg(windows)]
fn list_system_files(path: &PathBuf, recursive: bool) -> Vec<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    use winapi::um::winnt::FILE_ATTRIBUTE_SYSTEM;
    let mut system_files = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                if metadata.file_attributes() & FILE_ATTRIBUTE_SYSTEM != 0 {
                    system_files.push(entry_path.clone());
                }
                if recursive && metadata.is_dir() {
                    system_files.extend(list_system_files(&entry_path, true));
                }
            }
        }
    }
    system_files
}

#[cfg(windows)]
fn list_hidden_files(path: &PathBuf, recursive: bool) -> Vec<PathBuf> {
    use std::os::windows::fs::MetadataExt;
    use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;
    let mut hidden_files = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                if metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0 {
                    hidden_files.push(entry_path.clone());
                }
                if recursive && metadata.is_dir() {
                    hidden_files.extend(list_hidden_files(&entry_path, true));
                }
            }
        }
    }
    hidden_files
}

#[cfg(windows)]
fn list_locked_files(path: &PathBuf, recursive: bool) -> Vec<PathBuf> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::fs;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::shared::winerror::ERROR_SHARING_VIOLATION;
    use std::ptr::null_mut;

    let mut locked_files = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if recursive {
                        locked_files.extend(list_locked_files(&entry_path, true));
                    }
                } else {
                    let wide: Vec<u16> = OsStr::new(&entry_path)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    unsafe {
                        let handle = CreateFileW(
                            wide.as_ptr(),
                            GENERIC_READ | GENERIC_WRITE,
                            0, // no sharing
                            null_mut(),
                            OPEN_EXISTING,
                            0,
                            null_mut(),
                        );
                        // Use the literal value for INVALID_HANDLE_VALUE (-1isize as HANDLE)
                        if handle == (-1isize) as *mut _ {
                            let err = GetLastError();
                            if err == ERROR_SHARING_VIOLATION {
                                locked_files.push(entry_path.clone());
                            }
                        } else {
                            CloseHandle(handle);
                        }
                    }
                }
            }
        }
    }
    locked_files
}

#[cfg(windows)]
fn is_directory_locked(path: &PathBuf) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::shared::winerror::ERROR_SHARING_VIOLATION;
    use std::ptr::null_mut;

    let wide: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0, // no sharing
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            if err == ERROR_SHARING_VIOLATION {
                return true;
            }
        } else {
            CloseHandle(handle);
        }
    }
    false
}

fn is_protected_directory(dir_type: &str) -> bool {
    dir_type == "System"
}

fn is_hidden_directory(path: &PathBuf) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            return metadata.file_attributes() & winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN != 0;
        }
    }
    false
}

#[cfg(windows)]
fn clear_attributes_recursive(path: &PathBuf) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use winapi::um::winnt::{FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
    use winapi::um::fileapi::SetFileAttributesW;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::fs;

    if let Ok(metadata) = fs::metadata(path) {
        let attrs = metadata.file_attributes();
        let new_attrs = attrs & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        if new_attrs != attrs {
            let wide: Vec<u16> = OsStr::new(&path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                SetFileAttributesW(wide.as_ptr(), new_attrs);
            }
        }
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    clear_attributes_recursive(&entry.path())?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(path: &PathBuf) -> bool {
    use std::os::windows::fs::MetadataExt;
    use winapi::um::winnt::FILE_ATTRIBUTE_REPARSE_POINT;
    if let Ok(metadata) = std::fs::metadata(path) {
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    false
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.delete {
        println!("\nSearching for empty directories...");
        
        // Recursively delete empty directories
        let (deleted_count, skipped_count, error_count, failed_dirs) = if args.parallel {
            println!("Running in parallel delete mode...");
            recursive_delete_empty_dirs_parallel(&args.path, args.safe, args.force, args.verbose, args.delete_system_hidden)?
        } else {
            recursive_delete_empty_dirs(&args.path, args.safe, args.force, args.verbose, args.delete_system_hidden)?
        };
        println!("\nDeletion Summary:");
        println!("  Successfully deleted: {}", deleted_count);
        println!("  Skipped: {}", skipped_count);
        println!("  Errors: {}", error_count);
        
        if !failed_dirs.is_empty() {
            println!("\nDirectories that could not be deleted:");
            let mut found_system_or_hidden = false;
            for dir in &failed_dirs {
                if !dir.exists() { continue; } // Skip if directory was deleted after the fact
                // Print the root path as its full path, not as '.'
                if dir == &args.path {
                    println!("  - {} (root path specified)", dir.canonicalize().unwrap_or_else(|_| dir.clone()).display());
                } else {
                    println!("  - {}", dir.display());
                }
                #[cfg(windows)]
                if args.force {
                    let sys_files = list_system_files(dir, true);
                    let hidden_files = list_hidden_files(dir, true);
                    if !sys_files.is_empty() {
                        found_system_or_hidden = true;
                        println!("    System files in this directory:");
                        for f in &sys_files {
                            println!("      * {}", f.display());
                        }
                    }
                    if !hidden_files.is_empty() {
                        found_system_or_hidden = true;
                        println!("    Hidden files in this directory:");
                        for f in &hidden_files {
                            println!("      * {}", f.display());
                        }
                    }
                    let locked_files = list_locked_files(dir, true);
                    if !locked_files.is_empty() {
                        println!("    Locked files in this directory:");
                        for f in locked_files {
                            println!("      * {}", f.display());
                        }
                    }
                    if is_directory_locked(dir) {
                        println!("    The directory itself is locked (in use by another process).");
                    }
                }
            }
            if found_system_or_hidden && !args.force && !args.delete_system_hidden {
                println!("\nNote: Some directories contain system or hidden files. Try running again with the --force and --delete-system-hidden flags to attempt forced deletion of these directories.");
            } else if args.force {
                println!("\nNote: These directories may be protected by the system, in use by another process, or require special permissions to delete.");
            } else {
                println!("\nNote: These directories may be protected by the system, in use by another process, or require special permissions to delete.");
                println!("      Try running again with the --force flag to attempt forced deletion.");
            }
        }
    } else {
        // Just find and display empty directories
        find_empty_dirs(&args.path, args.verbose, args.safe)?;
    }

    Ok(())
}
