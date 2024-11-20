import os
import subprocess
from app.logger import logger

def decompile_apk(apk_path, output_dir):
    """
    Decompile the given APK file using apktool and jadx.
    
    Parameters:
    - apk_path: Path to the APK file.
    - output_dir: Directory where the decompiled output should be stored.
    
    Returns:
    - A tuple containing the paths to the apktool and JADX output directories.
    """
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Decompile with apktool
    apktool_output_dir = os.path.join(output_dir, "apktool")
    if not os.path.exists(apktool_output_dir):
        os.makedirs(apktool_output_dir)
    
    apktool_command = ["apktool", "d", apk_path, "-o", apktool_output_dir, "-f"]
    try:
        subprocess.check_call(apktool_command)
        logger.info(f"APK successfully decompiled with apktool at {apktool_output_dir}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during APK decompilation with apktool: {e}")
        return None, None

    # Decompile with JADX
    jadx_output_dir = os.path.join(output_dir, "jadx")
    if not os.path.exists(jadx_output_dir):
        os.makedirs(jadx_output_dir)
    
    jadx_command = ["jadx", "-d", jadx_output_dir, apk_path]
    try:
        subprocess.check_call(jadx_command)
        logger.info(f"APK successfully decompiled with JADX at {jadx_output_dir}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during APK decompilation with JADX: {e}")
        return apktool_output_dir, None

    return apktool_output_dir, jadx_output_dir
