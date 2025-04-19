# Radare2 Android DEX Strings Analyzer

A powerful Python script that uses radare2 to analyze Android DEX files and extract all strings with their hex memory addresses. Perfect for Android app reverse engineering, malware analysis, and DEX file inspection.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![radare2](https://img.shields.io/badge/radare2-required-green.svg)

## 📁 Table of Contents

- [Features](#features)
- [Author](#author)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Examples](#examples)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## ✨ Features

- 🔍 Analyzes multiple DEX files simultaneously
- 📍 Extracts strings with hex memory addresses
- 📄 Generates both text and JSON outputs
- 📊 Creates detailed analysis logs
- 🎯 Removes duplicate strings automatically
- 🚀 Fast batch processing
- 🏷️ Includes string type metadata (class names, string table, etc.)
- 💾 Organized output structure

## 👨‍💻 Author

**Riyad Mondol**

- 📱 Telegram: [https://t.me/reversesio](https://t.me/reversesio)
- 🌐 Website: [http://reversesio.com/](http://reversesio.com/) | [http://reversesio.shop/](http://reversesio.shop/)
- 📧 Email: riyadmondol2006@gmail.com
- 💼 Project Opportunities: [https://t.me/riyadmondol2006](https://t.me/riyadmondol2006)
- 📽️ YouTube: [https://www.youtube.com/@reversesio](https://www.youtube.com/@reversesio)

## 🔧 Prerequisites

- Python 3.6 or higher
- Radare2 installed and available in PATH

### Installing Radare2

#### Linux:
```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

#### macOS:
```bash
brew install radare2
```

#### Windows:
Download the installer from [radare2 GitHub releases](https://github.com/radareorg/radare2/releases)

## 📥 Installation

1. Clone this repository:
```bash
git clone https://github.com/riyadmondol2006/radare2-dex-strings-analyzer.git
cd radare2-dex-strings-analyzer
```

2. Make the script executable (Linux/macOS):
```bash
chmod +x RadareDexStringsAnalyzer.py
```

## 🚀 Usage

### Basic Usage

Run the script in the directory containing DEX files:
```bash
python3 RadareDexStringsAnalyzer.py
```

### Analyze Specific Directory

```bash
python3 RadareDexStringsAnalyzer.py /path/to/dex/files
```

## 📂 Output Structure

The script creates a `dex_string_analysis` directory with the following structure:
```
dex_string_analysis/
├── classes_dex_strings.txt               # Individual file results
├── classes2_dex_strings.txt
├── classes3_dex_strings.txt
├── ...
├── all_dex_strings_YYYYMMDD_HHMMSS.json  # All results in JSON format
└── dex_string_analysis_log_YYYYMMDD_HHMMSS.txt  # Processing log
```

### Output Format

Each string entry contains:
- **HEX ID**: Memory address of the string
- **SIZE**: String size in bytes
- **STRING**: The actual string content
- **TYPE**: String type (class, string_table, etc.)

## 📋 Examples

### Text Output Example:
```
File: classes.dex
Total strings: 3456
Timestamp: 2024-04-20 12:34:56
----------------------------------------------------------------------

HEX ID: 0x00003214
SIZE: 32
STRING: com.example.app.MainActivity
TYPE: class
--------------------------------------------------
HEX ID: 0x00003345
SIZE: 45
STRING: android.permission.INTERNET
TYPE: string_table
