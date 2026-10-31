"""Install the pinned upstream Katana binary locally after checksum verification."""
import hashlib
import io
from pathlib import Path
import platform
from urllib.request import urlopen
import zipfile


VERSION = "1.8.0"


def main():
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macOS"}.get(platform.system())
    arch = {"AMD64": "amd64", "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not system or not arch:
        raise SystemExit("Unsupported platform; install Katana v1.8.0 from its official releases")
    name = f"katana_{VERSION}_{system}_{arch}.zip"
    base = f"https://github.com/projectdiscovery/katana/releases/download/v{VERSION}/"
    with urlopen(base + name, timeout=60) as response:
        data = response.read()
    with urlopen(base + f"katana-{VERSION}-checksums.txt", timeout=30) as response:
        checksums = response.read().decode()
    digest = hashlib.sha256(data).hexdigest()
    if not any(line.split() == [digest, name] for line in checksums.splitlines()):
        raise SystemExit("Checksum mismatch; nothing installed")
    executable = "katana.exe" if system == "windows" else "katana"
    folder = Path(__file__).resolve().parents[1] / ".tools" / "katana"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / executable
    path.write_bytes(zipfile.ZipFile(io.BytesIO(data)).read(executable))
    path.chmod(0o755)
    print(f"Installed checksum-verified Katana v{VERSION}: {path}")


if __name__ == "__main__":
    main()
