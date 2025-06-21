# clean

A fast, robust Rust CLI tool to find and optionally delete empty directories, with special handling for system, cache, and backup directories. Supports Windows-specific features like system/hidden/locked file detection, force deletion, and diagnostics for undeletable directories.

## Features
- Finds empty directories recursively from a given path
- Optionally deletes empty directories (`--delete`)
- Parallel directory traversal and deletion (`--parallel`, `-p`)
- Special handling for system, cache, backup, and JetBrains/Chrome/GoTo/IsolatedStorage directories
- Diagnostics for undeletable directories (system, hidden, locked files, and locked directories)
- Force deletion by taking ownership and modifying permissions (`--force`)
- Optionally delete directories with system/hidden attributes or files (`--delete-system-hidden`)
- Verbose output for inspection (`--verbose`)
- Safe mode to only delete known safe directories (`--safe`)

## Usage

```sh
clean [OPTIONS] [PATH]
```

### Options
- `-d`, `--delete`                 Delete empty folders if set
- `-v`, `--verbose`                Show detailed information about directories
- `-s`, `--safe`                   Only delete directories known to be safe (cache, temp, etc.)
- `-f`, `--force`                  Force deletion by taking ownership and modifying permissions
- `--delete-system-hidden`         Allow deletion of system and hidden directories (DANGEROUS)
- `-p`, `--parallel`               Delete empty directories in parallel (experimental)

### Examples

- Find empty directories:
  ```sh
  clean
  ```
- Delete empty directories:
  ```sh
  clean --delete
  ```
- Delete in parallel (faster on large trees):
  ```sh
  clean --delete --parallel
  # or
  clean --delete -p
  ```
- Force delete and allow system/hidden:
  ```sh
  clean --delete --force --delete-system-hidden
  ```

## Safety
- By default, system and hidden directories are not deleted unless `--delete-system-hidden` is specified.
- Use `--safe` to restrict deletion to known safe directories (cache, temp, etc.).
- Use `--force` to attempt to take ownership and grant permissions before deleting.
- Use `--parallel`/`-p` for faster deletion on large directory trees (experimental).

## Building

```sh
cargo build --release
```

## License
MIT
