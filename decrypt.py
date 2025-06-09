#!/usr/bin/env python3

import re
import binascii
import base64
from typing import Optional, Tuple, Dict, Any
import os
import datetime

def decode_hex_stuff(hex_string: str) -> str:
    hex_string = hex_string.strip()
    if hex_string.startswith("exec(b'") and hex_string.endswith("')"):
        hex_string = hex_string[7:-2]
    elif hex_string.startswith('exec(b"') and hex_string.endswith('")'):
        hex_string = hex_string[7:-2]
        
    hex_pattern = r'\\x([0-9a-fA-F]{2})'
    hex_matches = re.findall(hex_pattern, hex_string)
        
    if not hex_matches:
        return "couldn't find any hex stuff"
        
    try:
        byte_data = bytes([int(hex_val, 16) for hex_val in hex_matches])
        return byte_data.decode('utf-8', errors='replace')
    except Exception as e:
        return f"broke while decoding hex: {str(e)}"

def grab_fernet_bits(code_string: str) -> Optional[Tuple[str, str]]:
    key_patterns = [
        r"Fernet\(b'([^']+)'\)",
        r"Fernet\('([^']+)'\)",
        r"Fernet\(b\"([^\"]+)\"\)",
        r"Fernet\(\"([^\"]+)\"\)"
    ]
        
    data_patterns = [
        r"\.decrypt\(b'([^']+)'\)",
        r"\.decrypt\('([^']+)'\)",
        r"\.decrypt\(b\"([^\"]+)\"\)",
        r"\.decrypt\(\"([^\"]+)\"\)"
    ]
        
    key_match = None
    data_match = None
        
    for pattern in key_patterns:
        key_match = re.search(pattern, code_string)
        if key_match:
            break
        
    for pattern in data_patterns:
        data_match = re.search(pattern, code_string)
        if data_match:
            break
        
    if key_match and data_match:
        return key_match.group(1), data_match.group(1)
        
    return None

def crack_fernet(key_b64: str, encrypted_data_b64: str) -> str:
    try:
        from cryptography.fernet import Fernet
                
        key_bytes = key_b64.encode('utf-8')
        fernet = Fernet(key_bytes)
                
        encrypted_bytes = encrypted_data_b64.encode('utf-8')
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
                
        return decrypted_bytes.decode('utf-8', errors='replace')
            
    except ImportError:
        return "need to install cryptography first - pip install cryptography"
    except Exception as e:
        return f"fernet decryption failed: {str(e)}"

def fix_messy_code(code_string: str) -> str:
    cleaned = code_string.replace(';', '\n')
        
    lines = [line.strip() for line in cleaned.split('\n') if line.strip()]
        
    return '\n'.join(lines)

def process_everything(input_string: str) -> Dict[str, Any]:
    results = {
        'original': input_string,
        'cleaned_code': '',
        'hex_decoded': '',
        'fernet_key': '',
        'fernet_encrypted': '',
        'fernet_decrypted': '',
        'final_payload': '',
        'analysis': []
    }
        
    current_string = input_string
    
    fernet_data = grab_fernet_bits(current_string)
        
    if fernet_data:
        results['cleaned_code'] = fix_messy_code(current_string)
        results['fernet_key'], results['fernet_encrypted'] = fernet_data
        results['analysis'].append("found fernet encryption right away")
                
        results['fernet_decrypted'] = crack_fernet(
            results['fernet_key'], 
            results['fernet_encrypted']
        )
        results['analysis'].append("tried to decrypt fernet")
                
        results['final_payload'] = results['fernet_decrypted']
            
    else:
        results['hex_decoded'] = decode_hex_stuff(current_string)
                
        if "couldn't find any hex stuff" not in results['hex_decoded']:
            results['analysis'].append("decoded some hex")
            current_string = results['hex_decoded']
        else:
            results['analysis'].append("no hex encoding here")
            current_string = input_string
                
        fernet_data = grab_fernet_bits(current_string)
                
        if fernet_data:
            results['fernet_key'], results['fernet_encrypted'] = fernet_data
            results['analysis'].append("found fernet key and data")
                        
            results['fernet_decrypted'] = crack_fernet(
                results['fernet_key'],
                results['fernet_encrypted']
            )
            results['analysis'].append("attempted fernet decryption")
            results['final_payload'] = results['fernet_decrypted']
        else:
            results['analysis'].append("no fernet encryption found")
            results['final_payload'] = current_string
        
    return results

def dump_results(results: Dict[str, Any], output_file: str = "decrypted_results.txt"):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("DECODER RESULTS\n")
        f.write("=" * 80 + "\n\n")
                
        f.write("what happened:\n")
        for step in results['analysis']:
            f.write(f"  - {step}\n")
        f.write("\n")
                
        f.write("original input:\n")
        f.write("-" * 50 + "\n")
        original_preview = results['original'][:300] + "..." if len(results['original']) > 300 else results['original']
        f.write(original_preview + "\n\n")
                
        if results['cleaned_code']:
            f.write("cleaned up code:\n")
            f.write("-" * 50 + "\n")
            f.write(results['cleaned_code'] + "\n\n")
                
        if results['hex_decoded'] and "couldn't find any hex stuff" not in results['hex_decoded']:
            f.write("hex decoded:\n")
            f.write("-" * 50 + "\n")
            f.write(results['hex_decoded'] + "\n\n")
                
        if results['fernet_key']:
            f.write("fernet key:\n")
            f.write("-" * 50 + "\n")
            f.write(results['fernet_key'] + "\n\n")
                        
            f.write("encrypted data (first 200 chars):\n")
            f.write("-" * 50 + "\n")
            encrypted_preview = results['fernet_encrypted'][:200] + "..." if len(results['fernet_encrypted']) > 200 else results['fernet_encrypted']
            f.write(encrypted_preview + "\n\n")
                
        if results['fernet_decrypted']:
            f.write("decrypted content:\n")
            f.write("-" * 50 + "\n")
            f.write(results['fernet_decrypted'] + "\n\n")
                
        f.write("final result:\n")
        f.write("-" * 50 + "\n")
        f.write(results['final_payload'] + "\n\n")
                
        f.write("=" * 80 + "\n")

def main():
    print("decoder thing")
    print("=" * 50)
    print("handles hex, fernet, and messy python code")
    print("paste your encoded stuff here (empty line to quit)")
        
    while True:
        print("\nwhat do you want to do:")
        print("1. paste string")
        print("2. load from file")
        print("3. quit")
                
        choice = input("\npick one (1-3): ").strip()
                
        if choice == '3' or not choice:
            print("bye")
            break
        elif choice == '1':
            user_input = input("\npaste your encoded string: ").strip()
            if not user_input:
                continue
        elif choice == '2':
            filename = input("filename: ").strip()
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    user_input = f.read().strip()
                print(f"loaded {len(user_input)} chars from {filename}")
            except Exception as e:
                print(f"couldn't read file: {e}")
                continue
        else:
            print("invalid choice")
            continue
                
        print("\nworking on it...")
        results = process_everything(user_input)
                
        print("\nwhat i did:")
        for step in results['analysis']:
            print(f"  - {step}")
                
        if results['cleaned_code']:
            print(f"\ncleaned code:\n{results['cleaned_code'][:500]}{'...' if len(results['cleaned_code']) > 500 else ''}")
                
        if results['fernet_key']:
            print(f"\nfernet key: {results['fernet_key']}")
            print(f"encrypted data size: {len(results['fernet_encrypted'])} chars")
                
        if results['fernet_decrypted']:
            print(f"\ndecrypted stuff:\n{results['fernet_decrypted']}")
                
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"results_{timestamp}.txt"
        dump_results(results, output_file)
        print(f"\nsaved to {output_file}")

if __name__ == "__main__":
    main()
