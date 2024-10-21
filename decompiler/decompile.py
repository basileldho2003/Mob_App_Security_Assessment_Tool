import subprocess
import os

def decompile_apk(apk_path, output_dir):
    """
    Decompile the given APK file using apktool and jadx.
    """
    try:
        # Ensure the output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Run apktool to decompile resources
        apktool_cmd = ["apktool", "d", apk_path, "-o", os.path.join(output_dir, "apktool_output"), "-f"]
        subprocess.run(apktool_cmd, check=True)

        # Run jadx to decompile dex files to Java source code
        jadx_cmd = ["jadx", "-d", os.path.join(output_dir, "jadx_output"), apk_path]
        subprocess.run(jadx_cmd, check=True)

        print("Decompilation completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error during decompilation: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Testing code (for development purposes)
# if __name__ == "__main__":
#     apk_path = "path/to/your.apk"
#     output_dir = "output_directory"
#     decompile_apk(apk_path, output_dir)
