#!/usr/bin/env python3
"""
File Integrity Checker - Verify file integrity with checksums and detect unauthorized changes.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
DEFAULT_ALGORITHM = "sha256"
MANIFEST_FILENAME = ".integrity_manifest.json"


class ProgressBar:
    """Simple text-based progress bar for long-running operations."""

    def __init__(self, total: int, desc: str = "", width: int = 30):
        self.total = total
        self.current = 0
        self.desc = desc
        self.width = width
        self._last_line_length = 0

    def update(self, n: int = 1) -> None:
        """Update progress by n steps."""
        self.current += n
        self._render()

    def _render(self) -> None:
        """Render the progress bar."""
        if self.total == 0:
            percent = 100
            filled = self.width
        else:
            percent = int(100 * self.current / self.total)
            filled = int(self.width * self.current / self.total)

        bar = "=" * filled + "-" * (self.width - filled)
        line = f"\r{self.desc}: [{bar}] {self.current}/{self.total} ({percent}%)"

        # Clear any leftover characters from previous render
        padding = max(0, self._last_line_length - len(line))
        self._last_line_length = len(line)

        sys.stdout.write(line + " " * padding)
        sys.stdout.flush()

    def close(self) -> None:
        """Finish and clear the progress bar line."""
        self._render()
        sys.stdout.write("\n")
        sys.stdout.flush()


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

    # First pass: collect all files to scan
    files_to_scan = []
    pattern = "**/*" if recursive else "*"

    for file_path in dir_path.glob(pattern):
        if file_path.is_symlink():
            continue

        if file_path.is_file():
            rel_path = str(file_path.relative_to(dir_path))

            if file_path.name == MANIFEST_FILENAME:
                continue

            if file_path.name.startswith("."):
                continue

            files_to_scan.append((file_path, rel_path))

    # Second pass: calculate checksums with progress bar
    progress = ProgressBar(len(files_to_scan), desc="Scanning")

    for file_path, rel_path in files_to_scan:
        try:
            checksum = calculate_checksum(str(file_path), algorithm)
            manifest["files"][rel_path] = {
                "checksum": checksum,
                "size": file_path.stat().st_size,
                "modified_time": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
        except (IOError, OSError) as e:
            print(f"Warning: Could not process {rel_path}: {e}", file=sys.stderr)

        progress.update()

    progress.close()

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
        if file_path.is_symlink():
            continue

        if file_path.is_file():
            rel_path = str(file_path.relative_to(dir_path))

            if file_path.name == MANIFEST_FILENAME:
                continue

            if file_path.name.startswith("."):
                continue

            current_files.add(rel_path)

    # Add progress bar for verification
    total_files = len(recorded_files)
    progress = ProgressBar(total_files, desc="Verifying")

    for rel_path in recorded_files:
        file_path = dir_path / rel_path

        if not file_path.exists():
            results["deleted"].append(rel_path)
            progress.update()
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

        progress.update()

    progress.close()

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


def create_command(args: argparse.Namespace) -> None:
    """Handle the 'create' command to generate a new manifest."""
    output_path = args.output if args.output else os.path.join(args.directory, MANIFEST_FILENAME)

    print(f"Scanning directory: {args.directory}")
    print(f"Using algorithm: {args.algorithm}")

    try:
        manifest = scan_directory(args.directory, args.algorithm)
        save_manifest(manifest, output_path)
        print(f"Manifest saved to: {output_path}")
        print(f"Total files recorded: {len(manifest['files'])}")
    except (FileNotFoundError, NotADirectoryError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def verify_command(args: argparse.Namespace) -> None:
    """Handle the 'verify' command to check files against a manifest."""
    manifest_path = args.manifest if args.manifest else os.path.join(args.directory, MANIFEST_FILENAME)

    print(f"Verifying directory: {args.directory}")
    print(f"Using manifest: {manifest_path}")

    try:
        manifest = load_manifest(manifest_path)
        results = verify_integrity(args.directory, manifest)
        print_verification_report(results)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid manifest file: {e}", file=sys.stderr)
        sys.exit(1)


def hash_command(args: argparse.Namespace) -> None:
    """Handle the 'hash' command to calculate or verify a single file's hash."""
    if os.path.islink(args.file):
        print(f"Error: Skipping symlink: {args.file}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.file):
        print(f"Error: Not a file: {args.file}", file=sys.stderr)
        sys.exit(1)

    try:
        actual_hash = calculate_checksum(args.file, args.algorithm)
    except (IOError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verify is not None:
        expected_hash = args.verify.lower()
        if actual_hash == expected_hash:
            print(f"OK: {args.file}")
            print(f"Algorithm: {args.algorithm}")
            print(f"Hash: {actual_hash}")
            sys.exit(0)
        else:
            print(f"FAILED: {args.file}")
            print(f"Algorithm: {args.algorithm}")
            print(f"Expected: {expected_hash}")
            print(f"Actual:   {actual_hash}")
            sys.exit(1)
    else:
        print(f"{actual_hash}  {args.file}")
        sys.exit(0)


def main():
    """Main entry point for the file integrity checker."""
    parser = argparse.ArgumentParser(
        prog="file_integrity",
        description="File Integrity Checker - Verify file integrity with checksums and detect unauthorized changes."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new integrity manifest")
    create_parser.add_argument("directory", help="Directory to scan")
    create_parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM})"
    )
    create_parser.add_argument("--output", help="Output path for the manifest file")
    create_parser.set_defaults(func=create_command)

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify files against existing manifest")
    verify_parser.add_argument("directory", help="Directory to verify")
    verify_parser.add_argument("--manifest", help="Path to manifest file")
    verify_parser.set_defaults(func=verify_command)

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Calculate or verify a single file's hash")
    hash_parser.add_argument("file", help="File to hash")
    hash_parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"Hash algorithm (default: {DEFAULT_ALGORITHM})"
    )
    hash_parser.add_argument("--verify", help="Expected hash value to verify against")
    hash_parser.set_defaults(func=hash_command)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
