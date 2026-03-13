#!/usr/bin/env python3
"""
File Integrity Checker - Verify file integrity with checksums and detect unauthorized changes.
"""

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
DEFAULT_ALGORITHM = "sha256"
MANIFEST_FILENAME = ".integrity_manifest.json"


def calculate_checksum(file_path: str, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Calculate the checksum of a file using the specified algorithm."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: {SUPPORTED_ALGORITHMS}")
    
    hash_func = hashlib.new(algorithm)
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except IOError as e:
        raise IOError(f"Failed to read file {file_path}: {e}")


def scan_directory(directory: str, algorithm: str = DEFAULT_ALGORITHM, recursive: bool = True) -> dict:
    """Scan a directory and calculate checksums for all files."""
    manifest = {
        "created_at": datetime.now().isoformat(),
        "algorithm": algorithm,
        "base_directory": os.path.abspath(directory),
        "files": {}
    }
    
    dir_path = Path(directory)
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory does not exist: {directory}")
    
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {directory}")
    
    pattern = "**/*" if recursive else "*"
    
    for file_path in dir_path.glob(pattern):
        if file_path.is_file():
            rel_path = str(file_path.relative_to(dir_path))
            
            if file_path.name == MANIFEST_FILENAME:
                continue
            
            if file_path.name.startswith("."):
                continue
            
            try:
                checksum = calculate_checksum(str(file_path), algorithm)
                manifest["files"][rel_path] = {
                    "checksum": checksum,
                    "size": file_path.stat().st_size,
                    "modified_time": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                }
            except (IOError, OSError) as e:
                print(f"Warning: Could not process {rel_path}: {e}", file=sys.stderr)
    
    return manifest


def save_manifest(manifest: dict, output_path: str) -> None:
    """Save the manifest to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)


def load_manifest(manifest_path: str) -> dict:
    """Load a manifest from a JSON file."""
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    
    with open(manifest_path, "r") as f:
        return json.load(f)


def verify_integrity(directory: str, manifest: dict) -> dict:
    """Verify files against a manifest and report any changes."""
    results = {
        "verified": [],
        "modified": [],
        "deleted": [],
        "added": [],
        "errors": []
    }
    
    dir_path = Path(directory)
    recorded_files = set(manifest.get("files", {}).keys())
    current_files = set()
    
    pattern = "**/*"
    for file_path in dir_path.glob(pattern):
        if file_path.is_file():
            rel_path = str(file_path.relative_to(dir_path))
            
            if file_path.name == MANIFEST_FILENAME:
                continue
            
            if file_path.name.startswith("."):
                continue
            
            current_files.add(rel_path)
    
    for rel_path in recorded_files:
        file_path = dir_path / rel_path
        
        if not file_path.exists():
            results["deleted"].append(rel_path)
            continue
        
        recorded_data = manifest["files"][rel_path]
        algorithm = manifest.get("algorithm", DEFAULT_ALGORITHM)
        
        try:
            current_checksum = calculate_checksum(str(file_path), algorithm)
            
            if current_checksum == recorded_data["checksum"]:
                results["verified"].append(rel_path)
            else:
                results["modified"].append({
                    "path": rel_path,
                    "expected": recorded_data["checksum"],
                    "actual": current_checksum
                })
        except (IOError, OSError) as e:
            results["errors"].append({"path": rel_path, "error": str(e)})
    
    for rel_path in current_files:
        if rel_path not in recorded_files:
            results["added"].append(rel_path)
    
    return results


def print_verification_report(results: dict) -> None:
    """Print a formatted verification report."""
    print("\n" + "=" * 60)
    print("FILE INTEGRITY VERIFICATION REPORT")
    print("=" * 60)
    
    print(f"\nVerified: {len(results['verified'])} files")
    print(f"Modified: {len(results['modified'])} files")
    print(f"Deleted:  {len(results['deleted'])} files")
    print(f"Added:    {len(results['added'])} files")
    print(f"Errors:   {len(results['errors'])} files")
    
    if results["modified"]:
        print("\n--- MODIFIED FILES ---")
        for item in results["modified"]:
            print(f"  [MODIFIED] {item['path']}")
            print(f"    Expected: {item['expected']}")
            print(f"    Actual:   {item['actual']}")
    
    if results["deleted"]:
        print("\n--- DELETED FILES ---")
        for path in results["deleted"]:
            print(f"  [DELETED] {path}")
    
    if results["added"]:
        print("\n--- ADDED FILES ---")
        for path in results["added"]:
            print(f"  [ADDED] {path}")
    
    if results["errors"]:
        print("\n--- ERRORS ---")
        for item in results["errors"]:
            print(f"  [ERROR] {item['path']}: {item['error']}")
    
    print("\n" + "=" * 60)
    
    has_issues = any([
        results["modified"],
        results["deleted"],
        results["added"],
        results["errors"]
    ])
    
    if has_issues:
        print("STATUS: INTEGRITY CHECK FAILED")
        sys.exit(1)
    else:
        print("STATUS: ALL FILES VERIFIED SUCCESSFULLY")
        sys.exit(0)


def create_command(args: list) -> None:
    """Handle the 'create' command to generate a new manifest."""
    if len(args) < 1:
        print("Usage: file_integrity.py create <directory> [--algorithm <algo>] [--output <path>]")
        sys.exit(1)
    
    directory = args[0]
    algorithm = DEFAULT_ALGORITHM
    output_path = None
    
    i = 1
    while i < len(args):
        if args[i] == "--algorithm" and i + 1 < len(args):
            algorithm = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        else:
            i += 1
    
    if output_path is None:
        output_path = os.path.join(directory, MANIFEST_FILENAME)
    
    print(f"Scanning directory: {directory}")
    print(f"Using algorithm: {algorithm}")
    
    try:
        manifest = scan_directory(directory, algorithm)
        save_manifest(manifest, output_path)
        print(f"Manifest saved to: {output_path}")
        print(f"Total files recorded: {len(manifest['files'])}")
    except (FileNotFoundError, NotADirectoryError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def verify_command(args: list) -> None:
    """Handle the 'verify' command to check files against a manifest."""
    if len(args) < 1:
        print("Usage: file_integrity.py verify <directory> [--manifest <path>]")
        sys.exit(1)
    
    directory = args[0]
    manifest_path = None
    
    i = 1
    while i < len(args):
        if args[i] == "--manifest" and i + 1 < len(args):
            manifest_path = args[i + 1]
            i += 2
        else:
            i += 1
    
    if manifest_path is None:
        manifest_path = os.path.join(directory, MANIFEST_FILENAME)
    
    print(f"Verifying directory: {directory}")
    print(f"Using manifest: {manifest_path}")
    
    try:
        manifest = load_manifest(manifest_path)
        results = verify_integrity(directory, manifest)
        print_verification_report(results)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid manifest file: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for the file integrity checker."""
    if len(sys.argv) < 2:
        print("File Integrity Checker")
        print("Usage: file_integrity.py <command> [options]")
        print("\nCommands:")
        print("  create <directory>   Create a new integrity manifest")
        print("  verify <directory>   Verify files against existing manifest")
        print("\nOptions:")
        print("  --algorithm <algo>   Hash algorithm (md5, sha1, sha256, sha512)")
        print("  --manifest <path>    Path to manifest file (for verify)")
        print("  --output <path>      Output path for manifest (for create)")
        sys.exit(0)
    
    command = sys.argv[1]
    args = sys.argv[2:]
    
    if command == "create":
        create_command(args)
    elif command == "verify":
        verify_command(args)
    else:
        print(f"Unknown command: {command}")
        print("Use 'create' or 'verify'")
        sys.exit(1)


if __name__ == "__main__":
    main()
