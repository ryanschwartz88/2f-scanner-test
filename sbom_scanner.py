#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
import datetime
import re

def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(
            command, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def check_tools_installed():
    """Check if Syft and Grype are installed."""
    tools = ["syft", "grype"]
    missing_tools = []
    
    for tool in tools:
        try:
            subprocess.run(
                f"{tool} --version", 
                shell=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL, 
                check=True
            )
        except subprocess.CalledProcessError:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"The following required tools are not installed: {', '.join(missing_tools)}")
        print("Please install them before running this script.")
        print("You can install them using:")
        print("  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin")
        print("  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin")
        sys.exit(1)

def create_output_directory(image_name):
    """Create a timestamped output directory for scan results."""
    # Clean image name for use in directory name (remove invalid characters)
    clean_image_name = re.sub(r'[^\w\-\.]', '_', image_name)
    
    # Create timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create directory name
    dir_name = f"scan_{timestamp}_{clean_image_name}"
    
    # Create the directory
    os.makedirs(dir_name, exist_ok=True)
    
    print(f"Created output directory: {dir_name}")
    return dir_name

def generate_sbom(image_name, output_dir, output_format="json"):
    """Generate SBOM for the given container image using Syft."""
    print(f"Generating SBOM for image: {image_name}")
    
    # Set output file path
    output_file = os.path.join(output_dir, f"sbom.{output_format}")
    output_option = f"-o {output_format}={output_file}"
    
    command = f"syft {image_name} {output_option}"
    run_command(command)
    
    print(f"SBOM generated and saved to: {output_file}")
    return output_file

def scan_vulnerabilities(image_name, sbom_file, output_dir, output_format="table"):
    """Scan for vulnerabilities using Grype with the generated SBOM."""
    print(f"Scanning for vulnerabilities in image: {image_name}")
    
    # Set output file path
    output_file = os.path.join(output_dir, f"vulnerabilities.{output_format}")
    
    # Adjust command based on output format
    if output_format == "table":
        # For table format, we need to redirect output
        command = f"grype sbom:{sbom_file} --output {output_format} > {output_file}"
    else:
        # For other formats, grype can write directly to file
        command = f"grype sbom:{sbom_file} --output {output_format} --file {output_file}"
    
    run_command(command)
    print(f"Vulnerability report saved to: {output_file}")
    
    # Display summary of findings
    try:
        if output_format == "json":
            with open(output_file, 'r') as f:
                data = json.load(f)
                matches = data.get('matches', [])
                if matches:
                    severity_counts = {}
                    for match in matches:
                        severity = match.get('vulnerability', {}).get('severity', 'unknown')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    print("\nVulnerability Summary:")
                    for severity, count in severity_counts.items():
                        print(f"  {severity.upper()}: {count}")
                    print(f"  TOTAL: {len(matches)}")
                else:
                    print("\nNo vulnerabilities found.")
        else:
            print("\nScan complete. Check the vulnerability report for details.")
    except Exception as e:
        print(f"Error parsing vulnerability report: {e}")

def main():
    parser = argparse.ArgumentParser(description="Generate SBOM and scan for vulnerabilities in container images")
    parser.add_argument("image", help="Container image to scan (e.g., alpine:latest)")
    parser.add_argument("--sbom-format", choices=["json", "cyclonedx-json", "spdx-json"], default="json",
                        help="SBOM output format (default: json)")
    parser.add_argument("--vuln-format", choices=["table", "json", "cyclonedx-json"], default="table",
                        help="Vulnerability report format (default: table)")
    parser.add_argument("--output-dir", help="Custom output directory (default: auto-generated)")
    
    args = parser.parse_args()
    
    # Check if required tools are installed
    check_tools_installed()
    
    # Create output directory
    output_dir = args.output_dir if args.output_dir else create_output_directory(args.image)
    
    # Generate SBOM
    sbom_file = generate_sbom(args.image, output_dir, args.sbom_format)
    
    # Scan for vulnerabilities
    scan_vulnerabilities(args.image, sbom_file, output_dir, args.vuln_format)
    
    print(f"\nAll scan results are available in the directory: {output_dir}")

if __name__ == "__main__":
    main()