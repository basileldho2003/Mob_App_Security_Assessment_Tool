import os
import subprocess

def decompile_apk(apk_file_path):
    output_dir = os.path.splitext(apk_file_path)[0] + '_decompiled'
    command = f"apktool d {apk_file_path} -o {output_dir}"
    subprocess.run(command, shell=True)
    return output_dir
