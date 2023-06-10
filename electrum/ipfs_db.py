import json
import os
import threading
import stat

from typing import Optional, Tuple

from .json_db import JsonDB, locked, modifier
from .util import standardize_path, test_read_write_permissions, profiler, os_chmod

class IPFSDBReadWriteError(Exception): pass

class IPFSDB(JsonDB):
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls._instance = super().__new__(cls)
            cls._instance.__init__(*args, **kwargs)
        return cls._instance

    @classmethod
    def initialize(cls, path: str):
        cls(path).logger.info('loaded IPFS database')

    @classmethod
    def get_instance(cls) -> 'IPFSDB':
        assert cls._instance
        return cls._instance

    def __init__(self, path: str):
        JsonDB.__init__(self, {})
        self.path = standardize_path(path)
        self._file_exists = bool(self.path and os.path.exists(self.path))
        try:
            test_read_write_permissions(self.path)
        except IOError as e:
            raise IPFSDBReadWriteError(e) from e
        if self.file_exists():
            with open(self.path, "r", encoding='utf-8') as f:
                raw = f.read()
                self.data = json.loads(raw)
    
    @locked
    @profiler
    def write(self) -> None:
        if threading.current_thread().daemon:
            self.logger.warning('daemon thread cannot write db')
            return
        if not self.modified():
            return
        temp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(temp_path, "w", encoding='utf-8') as f:
            json_str = self.dump()
            f.write(json_str)
            f.flush()
            os.fsync(f.fileno())

        try:
            mode = os.stat(self.path).st_mode
        except FileNotFoundError:
            mode = stat.S_IREAD | stat.S_IWRITE

        # assert that wallet file does not exist, to prevent wallet corruption (see issue #5082)
        if not self.file_exists():
            assert not os.path.exists(self.path)
        os.replace(temp_path, self.path)
        os_chmod(self.path, mode)
        self._file_exists = True
        self.logger.info(f"saved {self.path}")
        self.set_modified(False)

    def file_exists(self) -> bool:
        return self._file_exists

    @modifier
    def add_metadata(self, ipfs_hash: str, mime_type: Optional[str], bytes: int):
        self.data[ipfs_hash] = mime_type, bytes

    @locked
    def get_metadata(self, ipfs_hash: str) -> Optional[Tuple[Optional[str], bytes]]:
        return self.data.get(ipfs_hash, None)