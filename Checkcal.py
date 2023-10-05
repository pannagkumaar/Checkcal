import argparse
import hashlib
import os
import sys

def hash_file(filename, algorithms):
    """
    Calculate the specified hash algorithms of a file.
    """
    try:
        with open(filename, 'rb') as f:
            hashes = {alg: hashlib.new(alg) for alg in algorithms}
            while chunk := f.read(16 * 1024):
                for hash in hashes.values():
                    hash.update(chunk)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    return {alg: hash.hexdigest() for alg, hash in hashes.items()}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Calculate file hashes.')
    parser.add_argument('filename', help='the name of the file to hash')
    parser.add_argument('-a', '--algorithm', nargs='+', default=['sha1', 'sha256', 'md5'], help='the hash algorithm(s) to use')

    args = parser.parse_args()

    if not os.path.exists(args.filename):
        print('ERROR: File "%s" was not found!' % args.filename)
        sys.exit(1)

    hashes = hash_file(args.filename, args.algorithm)
    if hashes is not None:
        for alg, hash in hashes.items():
            print(f"{alg.upper()}: {hash}")
