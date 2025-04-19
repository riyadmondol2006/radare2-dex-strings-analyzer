#!/usr/bin/env python3
"""
Radare2 DEX String Analysis Script with Hex IDs
Author: Riyad Mondol
Telegram: https://t.me/reversesio
Website: http://reversesio.com/ http://reversesio.shop/
Contact Me: riyadmondol2006@gmail.com
Feel free to reach out to me on Telegram for any project opportunities: https://t.me/riyadmondol2006
"""

import os
import subprocess
import sys
import datetime
import json
from pathlib import Path

def run_r2_command(file_path, command):
    """Run a specific radare2 command on a file and return the output."""
    try:
        # Using radare2 batch mode with -q to run command and quit
        cmd = ['r2', '-q', '-c', command, file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout, result.stderr
    except Exception as e:
        return None, str(e)

def parse_dex_string_output(output):
    """Parse radare2 DEX string output to extract hex IDs, strings, and metadata."""
    strings_data = []
    
    if not output:
        return strings_data
    
    lines = output.strip().split('\n')
    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue
        
        # Parse radare2 formatted output
        parts = line.split(' ', 2)
        if len(parts) >= 3:
            try:
                # Handle various DEX output formats
                hex_id = parts[0]
                if hex_id.startswith('0x'):
                    size = parts[1]
                    string_content = parts[2].strip()
                    
                    # Clean up the string content
                    if string_content.startswith('"') and string_content.endswith('"'):
                        string_content = string_content[1:-1]
                    
                    strings_data.append({
                        'hex_id': hex_id,
                        'size': size,
                        'content': string_content
                    })
            except IndexError:
                continue
    
    return strings_data

def extract_dex_strings(file_path):
    """Extract all strings from a DEX file using specific radare2 commands."""
    all_strings = []
    
    # Commands to extract different types of strings from DEX files
    commands = [
        'izz',  # All strings from anywhere in the file
        'iz',   # Strings from data sections
        'is',   # Symbols (which might include string references)
        'icj',  # Classes in JSON format (might contain string references)
        'izq',  # Quick listing of strings
        'ir'    # References
    ]
    
    for cmd in commands:
        output, error = run_r2_command(file_path, cmd)
        
        # Handle JSON output for classes
        if cmd == 'icj' and output:
            try:
                json_data = json.loads(output)
                # Extract any strings from class metadata
                for entry in json_data:
                    if 'classname' in entry:
                        all_strings.append({
                            'hex_id': hex(entry.get('addr', 0)),
                            'size': 'N/A',
                            'content': entry['classname'],
                            'type': 'class'
                        })
            except json.JSONDecodeError:
                pass
        elif output:
            strings_data = parse_dex_string_output(output)
            all_strings.extend(strings_data)
    
    # Special handling for DEX string table
    output, error = run_r2_command(file_path, 'px @@ string.data')
    if output:
        # Parse the hexdump output for string data
        lines = output.strip().split('\n')
        for line in lines:
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    hex_part = parts[0].strip()
                    string_part = parts[1].strip()
                    
                    # Extract the address
                    addr_match = hex_part.split()
                    if addr_match and addr_match[0].startswith('0x'):
                        all_strings.append({
                            'hex_id': addr_match[0],
                            'size': 'N/A',
                            'content': string_part,
                            'type': 'string_table'
                        })
    
    # Remove duplicates based on content and hex_id
    seen = set()
    unique_strings = []
    for string in all_strings:
        key = (string['hex_id'], string['content'])
        if key not in seen:
            seen.add(key)
            unique_strings.append(string)
    
    # Sort by hex_id
    unique_strings.sort(key=lambda x: int(x['hex_id'], 16) if x['hex_id'].startswith('0x') else 0)
    
    return unique_strings

def analyze_dex_files(input_directory='.', output_directory='dex_string_analysis'):
    """Analyze all .dex files in the input directory and extract strings with hex IDs."""
    
    # Create output directory if it doesn't exist
    output_path = Path(output_directory)
    output_path.mkdir(exist_ok=True)
    
    # Create timestamp for log file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_path = output_path / f"dex_string_analysis_log_{timestamp}.txt"
    json_file_path = output_path / f"all_dex_strings_{timestamp}.json"
    
    # Get all .dex files in the directory
    dex_files = [f for f in os.listdir(input_directory) if f.endswith('.dex')]
    
    if not dex_files:
        print(f"No .dex files found in {input_directory}")
        return
    
    print(f"Found {len(dex_files)} .dex files to analyze")
    print(f"Output will be saved to {output_path}")
    print(f"Log file: {log_file_path}")
    print("-" * 70)
    
    all_results = {}
    
    with open(log_file_path, 'w') as log_file:
        log_file.write(f"DEX string analysis started at {datetime.datetime.now()}\n")
        log_file.write(f"Found {len(dex_files)} .dex files to analyze\n")
        log_file.write("-" * 70 + "\n\n")
        
        for index, file_name in enumerate(dex_files, 1):
            file_path = os.path.join(input_directory, file_name)
            base_name = os.path.splitext(file_name)[0]
            
            print(f"\n[{index}/{len(dex_files)}] Processing: {file_name}")
            log_file.write(f"\n[{index}/{len(dex_files)}] Processing: {file_name}\n")
            
            # Extract all strings with their hex IDs
            print(f"  Extracting strings and hex addresses from DEX...")
            strings_data = extract_dex_strings(file_path)
            
            if strings_data:
                # Save individual file results
                individual_file_path = output_path / f"{base_name}_dex_strings.txt"
                with open(individual_file_path, 'w') as f:
                    f.write(f"File: {file_name}\n")
                    f.write(f"Total strings: {len(strings_data)}\n")
                    f.write(f"Timestamp: {datetime.datetime.now()}\n")
                    f.write("-" * 70 + "\n\n")
                    
                    for entry in strings_data:
                        f.write(f"HEX ID: {entry['hex_id']}\n")
                        f.write(f"SIZE: {entry['size']}\n")
                        f.write(f"STRING: {entry['content']}\n")
                        if 'type' in entry:
                            f.write(f"TYPE: {entry['type']}\n")
                        f.write("-" * 50 + "\n")
                
                print(f"  Found {len(strings_data)} strings")
                print(f"  Results saved to: {individual_file_path}")
                log_file.write(f"  Found {len(strings_data)} strings\n")
                log_file.write(f"  Results saved to: {individual_file_path}\n")
                
                # Add to global results
                all_results[file_name] = strings_data
                
                # Display a preview
                print(f"  First 5 strings:")
                for entry in strings_data[:5]:
                    if len(entry['content']) > 50:
                        content_preview = entry['content'][:47] + "..."
                    else:
                        content_preview = entry['content']
                    print(f"    {entry['hex_id']} [{entry['size']}]: {content_preview}")
            else:
                print(f"  No strings found or error occurred")
                log_file.write(f"  No strings found or error occurred\n")
        
        # Save all results as JSON
        with open(json_file_path, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        log_file.write(f"\n\nDEX string analysis completed at {datetime.datetime.now()}\n")
        log_file.write(f"Global JSON results saved to: {json_file_path}\n")
    
    print("\n" + "-" * 70)
    print(f"DEX string analysis complete! Check the {output_directory} folder for results.")
    print(f"Log file saved to: {log_file_path}")
    print(f"All strings saved to: {json_file_path}")

if __name__ == "__main__":
    # Check if radare2 is installed
    try:
        subprocess.run(['r2', '-v'], capture_output=True)
    except FileNotFoundError:
        print("Error: radare2 is not installed or not in PATH")
        print("Please install radare2 first: https://github.com/radareorg/radare2")
        sys.exit(1)
    
    # Use current directory if no argument specified
    if len(sys.argv) > 1:
        input_dir = sys.argv[1]
    else:
        input_dir = '.'
    
    analyze_dex_files(input_dir)
