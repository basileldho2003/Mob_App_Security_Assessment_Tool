import subprocess

def decompile_apk(apk_path):
    output_dir = f'output/{apk_path.split("/")[-1].replace(".apk", "")}'
    command = f"apktool d {apk_path} -o {output_dir} --force"
    subprocess.run(command, shell=True, check=True)
    return output_dir
