"""Создаёт тестовые файлы и показывает сравнение с эталоном в терминале."""

import hashlib
from pathlib import Path
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def run(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True,
                            text=True, check=True, timeout=60)
    return result.stdout.rstrip()


def main():
    examples = ROOT / "examples"
    examples.mkdir(exist_ok=True)
    (examples / "small.txt").write_bytes(b"abc")
    # 2 MiB: все значения байта 0..255, повторённые 8192 раза.
    (examples / "large.bin").write_bytes(bytes(range(256)) * 8192)

    print(run(["openssl", "version"]), flush=True)
    for name, label in [("small.txt", "Малый файл, 3 байта"),
                        ("large.bin", "Большой файл, 2 097 152 байта (> 1 МБ)")]:
        path = f"examples/{name}"
        commands = [["wc", "-c", path], ["./build/sha3sum", path],
                    ["openssl", "dgst", "-sha3-256", path]]
        outputs = [run(command) for command in commands]
        own = outputs[1].split()[0]
        reference = outputs[2].split()[-1]
        python_reference = hashlib.sha3_256((ROOT / path).read_bytes()).hexdigest()
        if own != reference or own != python_reference:
            raise RuntimeError(f"Digest mismatch: {path}")
        print(f"\n{label}")
        print("\n\n".join(
            f"$ {shlex.join(command)}\n{output}"
            for command, output in zip(commands, outputs)
        ))
        print("\nСравнение: PASS (C = OpenSSL = Python hashlib)")


if __name__ == "__main__":
    main()
