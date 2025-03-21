# Container SBOM and Vulnerability Scanner

This application generates a Software Bill of Materials (SBOM) for a container image using Syft and then scans for vulnerabilities using Grype.

## Prerequisites

- Python 3.6+
- Syft - For SBOM generation
- Grype - For vulnerability scanning

### Installing Syft and Grype

```bash
# Install Syft (Windows with Scoop)
scoop install syft

# Install Grype 
choco install grype

```

## Installation

1. Clone this repository
2. Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python sbom_scanner.py [IMAGE] [OPTIONS]
```

### Arguments

- `IMAGE`: Container image to scan (e.g., alpine:latest)

### Options

- `--sbom-format`: SBOM output format (json, cyclonedx-json, spdx-json) (default: json)
- `--vuln-format`: Vulnerability report format (table, json, cyclonedx-json) (default: table)
- `--output-dir`: Custom output directory (default: auto-generated timestamped directory)

### Examples

```bash
# Basic usage - scan alpine:latest and display vulnerabilities in table format
python sbom_scanner.py alpine:latest

# Generate SBOM in CycloneDX format
python sbom_scanner.py nginx:latest --sbom-format cyclonedx-json

# Generate SBOM and save vulnerability report in JSON format
python sbom_scanner.py ubuntu:20.04 --vuln-format json

# Specify a custom output directory
python sbom_scanner.py debian:latest --output-dir my_scan_results
```

## How It Works

1. The application takes a container image as input
2. It creates a timestamped directory to store scan results
3. It generates an SBOM using Syft and saves it in the output directory
4. It then scans for vulnerabilities using Grype with the generated SBOM and saves the report in the output directory
5. Results are displayed in the console and saved to files for later reference