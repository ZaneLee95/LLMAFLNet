import os
import re

BASE_DIR = "./vuln_patterns"

def check_file_format(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    has_target_messages = False
    has_pattern_section = False
    in_pattern_section = False
    pattern_lines = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("DESCRIPTION:"):
            continue
        elif stripped.startswith("TARGET_MESSAGES:"):
            has_target_messages = True
        elif stripped.startswith("PATTERN:"):
            has_pattern_section = True
            in_pattern_section = True
        elif in_pattern_section:
            if stripped == "":
                continue
            pattern_lines += 1

    errors = []
    if not has_target_messages:
        errors.append("❌ 缺少 TARGET_MESSAGES 字段")
    if not has_pattern_section:
        errors.append("❌ 缺少 PATTERN 段")
    elif pattern_lines == 0:
        errors.append("❌ PATTERN 段为空")

    return errors


def scan_all_vuln_files():
    for protocol in os.listdir(BASE_DIR):
        protocol_path = os.path.join(BASE_DIR, protocol)
        if not os.path.isdir(protocol_path):
            continue

        print(f"\n🛰 正在检查协议: {protocol}")
        for fname in os.listdir(protocol_path):
            if not fname.endswith(".txt"):
                continue
            full_path = os.path.join(protocol_path, fname)
            errors = check_file_format(full_path)
            if errors:
                print(f"  🚫 {fname}")
                for e in errors:
                    print(f"     {e}")
            else:
                print(f"  ✅ {fname} 格式正确")


if __name__ == "__main__":
    scan_all_vuln_files()
