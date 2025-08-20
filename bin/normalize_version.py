#!/usr/bin/env python3
# coding=utf-8
"""SemVer version normalization and comparison utility.

This script normalizes semantic versioning strings into standardized formats
and provides version comparison capabilities while maintaining backward compatibility.
"""

import argparse
import re
import sys
from typing import Dict, Optional, Union

def parse_semver(version_str: str) -> Dict[str, Union[int, str]]:
    """Parse a semantic version string into its components.
    
    Args:
        version_str: A semantic version string (e.g., '1.2.3-alpha+build.1')
        
    Returns:
        Dictionary with keys: major, minor, patch, prerelease, build
        
    Raises:
        ValueError: If the version string is not valid SemVer format
    """
    # Regex pattern to match SemVer 2.0.0 specification
    semver_regex = r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'
    match = re.match(semver_regex, version_str)
    
    if match:
        major, minor, patch, prerelease, build = match.groups()
        return {
            "major": int(major),
            "minor": int(minor),
            "patch": int(patch),
            "prerelease": prerelease if prerelease is not None else '',
            "build": build if build is not None else ''
        }
    else:
        raise ValueError(f"'{version_str}' is not a valid SemVer version.")



def calc_normalized_semver_version(version: str) -> str:
    """Normalize a semantic version into a fixed-width sortable format.
    
    Args:
        version: A semantic version string
        
    Returns:
        Normalized version string in format MMMMMMPPP + qualifier
        where MMM=major (3 digits), MMM=minor (3 digits), PP=patch (2 digits)
        
    Example:
        '1.2.3-alpha' -> '001002003alpha'
    """
    semver_version = parse_semver(version)
    qualifier = semver_version['prerelease'] or semver_version['build'] or ''
    return f"{semver_version['major']:0>3}{semver_version['minor']:0>3}{semver_version['patch']:0>2}{qualifier}"

def compare_versions(version1: str, version2: str) -> int:
    """Compare two semantic versions.
    
    Args:
        version1: First version to compare
        version2: Second version to compare
        
    Returns:
        -1 if version1 < version2, 0 if equal, 1 if version1 > version2
    """
    v1 = parse_semver(version1)
    v2 = parse_semver(version2)
    
    # Compare major.minor.patch
    for component in ['major', 'minor', 'patch']:
        if v1[component] < v2[component]:
            return -1
        elif v1[component] > v2[component]:
            return 1
    
    # Handle prerelease comparison (prerelease versions have lower precedence)
    if v1['prerelease'] and not v2['prerelease']:
        return -1
    elif not v1['prerelease'] and v2['prerelease']:
        return 1
    elif v1['prerelease'] and v2['prerelease']:
        if v1['prerelease'] < v2['prerelease']:
            return -1
        elif v1['prerelease'] > v2['prerelease']:
            return 1
    
    return 0


def format_version(version: str, format_type: str = 'normalized') -> str:
    """Format a version string in different ways.
    
    Args:
        version: Input version string
        format_type: Output format ('normalized', 'sortable', 'original', 'json')
        
    Returns:
        Formatted version string
    """
    if format_type == 'normalized':
        return calc_normalized_semver_version(version)
    elif format_type == 'sortable':
        # Alternative sortable format with dots
        parsed = parse_semver(version)
        qualifier = parsed['prerelease'] or parsed['build'] or ''
        return f"{parsed['major']:03d}.{parsed['minor']:03d}.{parsed['patch']:02d}{qualifier}"
    elif format_type == 'original':
        # Validate and return original (useful for validation-only mode)
        parse_semver(version)  # This will raise ValueError if invalid
        return version
    elif format_type == 'json':
        import json
        return json.dumps(parse_semver(version))
    else:
        raise ValueError(f"Unknown format type: {format_type}")


def process_versions_batch(versions, format_type: str = 'normalized'):
    """Process multiple versions from a list or stdin.
    
    Args:
        versions: Iterable of version strings
        format_type: Output format type
        
    Yields:
        Formatted version strings
    """
    for version in versions:
        version = version.strip()
        if version and not version.startswith('#'):
            try:
                yield format_version(version, format_type)
            except ValueError as e:
                print(f"Error processing '{version}': {e}", file=sys.stderr)


def main():
    """Main function with CLI interface."""
    parser = argparse.ArgumentParser(
        description='Normalize and compare semantic version strings',
        epilog='''Examples:
  %(prog)s 1.2.3                    # Output: 001002003
  %(prog)s 1.2.3 --format sortable  # Output: 001.002.03
  %(prog)s --compare 1.2.3 2.0.0    # Output: -1
  %(prog)s --batch < versions.txt    # Process multiple versions
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('version', nargs='?',
                        help='Version string to normalize (required unless using --batch)')
    parser.add_argument('--format', choices=['normalized', 'sortable', 'original', 'json'],
                        default='normalized',
                        help='Output format (default: normalized)')
    parser.add_argument('--compare', metavar='VERSION2',
                        help='Compare version with another version')
    parser.add_argument('--batch', action='store_true',
                        help='Process multiple versions from stdin')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output for debugging')
    
    # Check for legacy usage (backward compatibility)
    if len(sys.argv) == 2 and not sys.argv[1].startswith('-'):
        # Legacy mode: single argument, no flags
        try:
            print(calc_normalized_semver_version(sys.argv[1]))
            sys.exit(0)
        except ValueError as e:
            if '--verbose' in sys.argv or '-v' in sys.argv:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    args = parser.parse_args()
    
    try:
        if args.batch:
            # Batch processing from stdin
            versions = sys.stdin.readlines()
            for result in process_versions_batch(versions, args.format):
                print(result)
        elif args.compare:
            # Version comparison mode
            if not args.version:
                parser.error('Version argument required for comparison')
            result = compare_versions(args.version, args.compare)
            if args.verbose:
                symbols = {-1: '<', 0: '==', 1: '>'}
                print(f"{args.version} {symbols[result]} {args.compare}")
            print(result)
        else:
            # Single version processing
            if not args.version:
                parser.error('Version argument required (use --batch for stdin processing)')
            result = format_version(args.version, args.format)
            print(result)
            
    except ValueError as e:
        if args.verbose:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)  # Standard exit code for Ctrl+C


if __name__ == '__main__':
    main()
