import os
import hashlib
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class BinaryDiffHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, block_size=1024):
        self.watch_dir = watch_dir
        self.block_size = block_size  # Size of chunks to compare (in bytes)
        self.file_fingerprints = {}
        self._initial_scan()

    def _get_binary_fingerprint(self, path):
        """Divides a file into blocks and returns a list of hashes."""
        fingerprints = []
        try:
            with open(path, 'rb') as f:
                while True:
                    data = f.read(self.block_size)
                    if not data:
                        break
                    # Generate a quick SHA-1 hash for the block
                    fingerprints.append(hashlib.sha1(data).digest())
            return fingerprints
        except (FileNotFoundError, PermissionError):
            return None

    def _initial_scan(self):
        for filename in os.listdir(self.watch_dir):
            path = os.path.join(self.watch_dir, filename)
            if os.path.isfile(path):
                self.file_fingerprints[path] = self._get_binary_fingerprint(path)

    def on_modified(self, event):
        if not event.is_directory:
            path = event.src_path
            new_fingerprint = self._get_binary_fingerprint(path)
            old_fingerprint = self.file_fingerprints.get(path)

            if new_fingerprint and old_fingerprint:
                # Compare blocks
                total_blocks = len(new_fingerprint)
                # Count how many block hashes differ at the same index
                changed_blocks = sum(1 for i, j in zip(old_fingerprint, new_fingerprint) if i != j)

                # Account for size changes if any (though you mentioned they stay the same)
                size_diff = abs(len(new_fingerprint) - len(old_fingerprint))
                total_changes = changed_blocks + size_diff

                change_percent = (total_changes / max(total_blocks, 1)) * 100

                if total_changes > 0:
                    print(f"[BINARY CHANGE] {path}")
                    print(f"  Blocks changed: {changed_blocks}/{total_blocks}")
                    print(f"  Approximate change magnitude: {change_percent:.2f}%")
                    print("-" * 30)

                self.file_fingerprints[path] = new_fingerprint

if __name__ == "__main__":
    path_to_watch = "blobs"
    # Use a smaller block_size for higher precision, larger for performance
    handler = BinaryDiffHandler(path_to_watch, block_size=512)
    observer = Observer()
    observer.schedule(handler, path_to_watch, recursive=False)

    print(f"Monitoring binary integrity in: {os.path.abspath(path_to_watch)}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()