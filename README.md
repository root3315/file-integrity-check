# File Integrity Checker

Quick tool I wrote to verify file integrity with checksums and catch any unauthorized changes. Useful for monitoring directories, detecting tampering, or just making sure your backups haven't gone sideways.

## What It Does

- Generates checksums (MD5, SHA1, SHA256, SHA512) for all files in a directory
- Stores the checksums in a JSON manifest file
- Later verifies files against that manifest
- Reports modified, deleted, and newly added files
- Calculate or verify hash of individual files

## Quick Start

### Create a baseline manifest

```bash
python file_integrity.py create /path/to/monitor
```

This scans the directory and creates `.integrity_manifest.json` with checksums for every file.

### Verify files later

```bash
python file_integrity.py verify /path/to/monitor
```

Compares current files against the manifest and tells you what changed.

## Command Options

### Create command

```bash
python file_integrity.py create <directory> [--algorithm <algo>] [--output <path>]
```

- `--algorithm`: Choose hash algorithm (default: sha256). Options: md5, sha1, sha256, sha512
- `--output`: Custom output path for the manifest file

Example with custom algorithm:
```bash
python file_integrity.py create ./myproject --algorithm sha512
```

### Verify command

```bash
python file_integrity.py verify <directory> [--manifest <path>]
```

- `--manifest`: Custom path to the manifest file if it's not in the default location

### Hash command

```bash
python file_integrity.py hash <file> [--algorithm <algo>] [--verify <expected_hash>]
```

- `--algorithm`: Choose hash algorithm (default: sha256). Options: md5, sha1, sha256, sha512
- `--verify`: Expected hash value to verify against

Calculate hash of a file:
```bash
python file_integrity.py hash ./myfile.txt
```

Verify a file against a known hash:
```bash
python file_integrity.py hash ./myfile.txt --verify abc123...
```

Exit code is 0 if hash matches (or just calculated), 1 if verification fails.

## Output

The verify command prints a report showing:

- Files that passed verification
- Modified files (with expected vs actual checksums)
- Deleted files
- Newly added files
- Any read errors

Exit code is 0 if everything checks out, 1 if any issues found. Handy for CI/CD pipelines.

## Manifest Format

The manifest is just JSON, so you can inspect it if needed:

```json
{
  "created_at": "2026-03-13T10:30:00.123456",
  "algorithm": "sha256",
  "base_directory": "/absolute/path/to/dir",
  "files": {
    "src/main.py": {
      "checksum": "abc123...",
      "size": 1024,
      "modified_time": "2026-03-13T09:00:00"
    }
  }
}
```

## Notes

- Skips hidden files (starting with `.`)
- Skips the manifest file itself during scanning
- Recursive by default, scans all subdirectories
- Reads files in 8KB chunks so it handles large files fine

## Why I Built This

Needed something lightweight to monitor a deployment directory and make sure nobody sneaks in changes. Didn't want to install heavy tools or deal with complex configs. This does exactly what I need.
