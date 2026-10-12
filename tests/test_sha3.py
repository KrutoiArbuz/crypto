"""Проверки файлового CLI, известных векторов и сравнение с OpenSSL."""

import argparse
import hashlib
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest


parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
args = parser.parse_args()
BINARY = str(Path(args.binary).resolve())


class Sha3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sha3-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def run_hash(self, *arguments, **kwargs):
        return subprocess.run(
            [BINARY, *map(str, arguments)],
            capture_output=True, check=False, timeout=30, **kwargs
        )

    def check_data(self, data, expected=None):
        path = self.directory / "input.bin"
        path.write_bytes(data)
        result = self.run_hash(path)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        digest = result.stdout[:64].decode("ascii")
        self.assertEqual(result.stdout[64:], f"  {path}\n".encode())
        self.assertEqual(digest, hashlib.sha3_256(data).hexdigest())
        if expected is not None:
            self.assertEqual(digest, expected)
        reference = subprocess.run(
            ["openssl", "dgst", "-sha3-256", str(path)],
            capture_output=True, check=True, timeout=30
        )
        self.assertEqual(digest, reference.stdout.decode().split()[-1])

    def test_known_vectors(self):
        vectors = [
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            (b"a" * 1_000_000,
             "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
        ]
        for data, expected in vectors:
            with self.subTest(size=len(data)):
                self.check_data(data, expected)

    def test_block_and_read_boundaries(self):
        # Включены все остатки длины по модулю 136, полный блок и границы fread.
        sizes = [*range(1, 138), 270, 271, 272, 273, 8191, 8192, 8193,
                 16383, 16384, 16385, 2 * 1024 * 1024 + 17]
        for size in sizes:
            with self.subTest(size=size):
                self.check_data(bytes(range(256)) * (size // 256)
                                + bytes(range(size % 256)))

    def test_random_binary_files(self):
        generator = random.Random(20261006)
        for case in range(20):
            data = generator.randbytes(generator.randrange(0, 50000))
            with self.subTest(case=case, size=len(data)):
                self.check_data(data)

    def test_invalid_arguments(self):
        for arguments in [(), ("one", "two")]:
            with self.subTest(arguments=arguments):
                result = self.run_hash(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Usage:", result.stderr)

    def test_missing_file(self):
        result = self.run_hash(self.directory / "missing.bin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"cannot open", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX directory read check")
    def test_read_error(self):
        result = self.run_hash(self.directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"cannot read", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX filename check")
    def test_filename_escaping(self):
        name = "space %s\\\n\r\t\x1b\x7f.bin"
        path = self.directory / name
        path.write_bytes(b"abc")
        result = self.run_hash(name, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, (
            hashlib.sha3_256(b"abc").hexdigest()
            + "  space %s\\\\\\n\\r\\t\\x1b\\x7f.bin\n"
        ).encode())
        path.unlink()
        result = self.run_hash(name, cwd=self.directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertEqual(result.stderr.count(b"\n"), 1)

    @unittest.skipUnless(Path("/dev/full").exists(), "Requires /dev/full")
    def test_output_error(self):
        path = self.directory / "input.bin"
        path.write_bytes(b"abc")
        with open("/dev/full", "wb") as output:
            result = subprocess.run(
                [BINARY, str(path)], stdout=output, stderr=subprocess.PIPE,
                check=False, timeout=30
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"cannot write output", result.stderr)


if __name__ == "__main__":
    unittest.main(argv=["test_sha3.py"], verbosity=2)
