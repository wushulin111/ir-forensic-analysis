#!/usr/bin/env python3
"""
应急响应取证文件解压脚本
支持 Linux (tar.gz) 和 Windows (zip) 格式
"""

import os
import sys
import tarfile
import zipfile
import argparse
import shutil
from pathlib import Path


def extract_tar_gz(archive_path: str, output_dir: str) -> dict:
    """
    解压 tar.gz 文件
    
    Args:
        archive_path: tar.gz 文件路径
        output_dir: 输出目录
        
    Returns:
        dict: 包含解压结果的信息
    """
    result = {
        "success": False,
        "extracted_path": "",
        "txt_files": [],
        "error": ""
    }
    
    try:
        # 创建输出目录
        extract_path = Path(output_dir) / Path(archive_path).stem.replace('.tar', '')
        extract_path.mkdir(parents=True, exist_ok=True)
        
        # 解压文件
        with tarfile.open(archive_path, 'r:gz') as tar:
            tar.extractall(path=extract_path)
        
        result["success"] = True
        result["extracted_path"] = str(extract_path)
        
        # 查找所有txt文件
        for txt_file in extract_path.rglob("*.txt"):
            result["txt_files"].append(str(txt_file))
            
        print(f"[+] 成功解压: {archive_path}")
        print(f"[+] 解压路径: {extract_path}")
        print(f"[+] 发现 {len(result['txt_files'])} 个 txt 文件")
        
    except Exception as e:
        result["error"] = str(e)
        print(f"[-] 解压失败: {e}")
        
    return result


def extract_zip(archive_path: str, output_dir: str) -> dict:
    """
    解压 zip 文件
    
    Args:
        archive_path: zip 文件路径
        output_dir: 输出目录
        
    Returns:
        dict: 包含解压结果的信息
    """
    result = {
        "success": False,
        "extracted_path": "",
        "txt_files": [],
        "error": ""
    }
    
    try:
        # 创建输出目录
        extract_path = Path(output_dir) / Path(archive_path).stem.replace('.zip', '')
        extract_path.mkdir(parents=True, exist_ok=True)
        
        # 解压文件
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(path=extract_path)
        
        result["success"] = True
        result["extracted_path"] = str(extract_path)
        
        # 查找所有txt文件
        for txt_file in extract_path.rglob("*.txt"):
            result["txt_files"].append(str(txt_file))
            
        print(f"[+] 成功解压: {archive_path}")
        print(f"[+] 解压路径: {extract_path}")
        print(f"[+] 发现 {len(result['txt_files'])} 个 txt 文件")
        
    except Exception as e:
        result["error"] = str(e)
        print(f"[-] 解压失败: {e}")
        
    return result


def auto_extract(archive_path: str, output_dir: str = "./extracted") -> dict:
    """
    自动识别并解压取证文件
    
    Args:
        archive_path: 取证文件路径
        output_dir: 输出目录
        
    Returns:
        dict: 包含解压结果的信息
    """
    archive_path = Path(archive_path)
    
    if not archive_path.exists():
        return {
            "success": False,
            "error": f"文件不存在: {archive_path}"
        }
    
    # 根据扩展名选择解压方式
    suffix = archive_path.suffix.lower()
    name = archive_path.name.lower()
    
    if name.endswith('.tar.gz') or name.endswith('.tgz'):
        return extract_tar_gz(str(archive_path), output_dir)
    elif suffix == '.zip':
        return extract_zip(str(archive_path), output_dir)
    else:
        return {
            "success": False,
            "error": f"不支持的文件格式: {suffix}"
        }


def main():
    parser = argparse.ArgumentParser(description='应急响应取证文件解压工具')
    parser.add_argument('archive', help='取证文件路径 (tar.gz 或 zip)')
    parser.add_argument('--output', '-o', default='./extracted', help='输出目录')
    parser.add_argument('--type', '-t', choices=['tar.gz', 'zip', 'auto'], 
                        default='auto', help='压缩包类型 (默认自动识别)')
    
    args = parser.parse_args()
    
    if args.type == 'auto':
        result = auto_extract(args.archive, args.output)
    elif args.type == 'tar.gz':
        result = extract_tar_gz(args.archive, args.output)
    else:
        result = extract_zip(args.archive, args.output)
    
    if result["success"]:
        print("\n[+] 解压完成!")
        print(f"    路径: {result['extracted_path']}")
        print(f"    TXT文件数: {len(result['txt_files'])}")
        sys.exit(0)
    else:
        print(f"\n[-] 解压失败: {result['error']}")
        sys.exit(1)


if __name__ == '__main__':
    main()
