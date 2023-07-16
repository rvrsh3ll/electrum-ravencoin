import json
import os
import threading
import stat
import attr
import asyncio
import time

from typing import Optional, Tuple, TYPE_CHECKING, Set, Dict

from aiohttp import ClientResponse, ClientResponseError

from .bitcoin import base_decode
from .json_db import JsonDB, locked, modifier, StoredObject, StoredDict
from .util import standardize_path, test_read_write_permissions, profiler, os_chmod, ipfs_explorer_URL, event_listener, make_dir, EventListener
from .network import Network

from electrum import util

if TYPE_CHECKING:
    from .address_synchronizer import AddressSynchronizer

_VIEWABLE_MIMES = ('image/*', 'text/plain', 'application/json')

def is_mime_viewable(mime_type: str) -> bool:
    if not mime_type: return False
    for good in _VIEWABLE_MIMES:
        if '*' in good:
            start = good.split('*')[0]
            if mime_type.startswith(start):
                return True
        else:
            if good == mime_type:
                return True
    return False

def human_readable_size(size, decimal_places=3, greater_than=False):
    if not size: return None
    if not isinstance(size, int):
        return 'Unknown'
    for unit in ['Bytes','KiB','MiB','GiB','TiB']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{'>' if greater_than else ''}{size:.{decimal_places}g} {unit}"

@attr.s
class IPFSMetadata(StoredObject):
    known_size = attr.ib(default=None, type=int, validator=attr.validators.optional(attr.validators.instance_of(int)))
    over_sized = attr.ib(default=False, type=bool, validator=attr.validators.instance_of(bool))
    known_mime = attr.ib(default=None, type=str, validator=attr.validators.optional(attr.validators.instance_of(str)))
    is_client_side = attr.ib(default=False, type=bool, validator=attr.validators.instance_of(bool))
    last_attemped_query = attr.ib(default=None, type=int, validator=attr.validators.optional(attr.validators.instance_of(int)))
    info_lookup_successful = attr.ib(default=False, type=bool, validator=attr.validators.instance_of(bool))
    associated_assets = attr.ib(default=set(), type=Set[str], converter=set)

class IPFSDBReadWriteError(Exception): pass

class IPFSDB(JsonDB, EventListener):
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls._instance = super().__new__(cls)
            cls._instance.__init__(*args, **kwargs)
        return cls._instance

    @classmethod
    def initialize(cls, path: str, raw_path: str):
        cls(path, raw_path).logger.info('loaded IPFS database')

    @classmethod
    def get_instance(cls) -> 'IPFSDB':
        assert cls._instance
        return cls._instance

    def __init__(self, path: str, raw_path: str):
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
                self.data: Dict[str, IPFSMetadata] = StoredDict(json.loads(raw), self, [])

        self.raw_ipfs_path = standardize_path(raw_path)
        make_dir(self.raw_ipfs_path, False)

        self._ipfs_lookup_semaphore = asyncio.Semaphore()
        self._ipfs_lookup_current = set()
        self._ipfs_download_current = set()

        self.register_callbacks()
    
    def _should_convert_to_stored_dict(self, key) -> bool:
        return False

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
    
    def _convert_dict(self, path, key, v):
        v = IPFSMetadata(**v)
        return v
    
    def _append_bytes_to_raw_ipfs_file(self, ipfs_hash: str, b: bytes):
        ipfs_file = standardize_path(os.path.join(self.raw_ipfs_path, ipfs_hash))
        with open(ipfs_file, 'ab') as f:
            f.write(b)

    @locked
    def purge_stale_ipfs_data(self):
        stale_hashes = {ipfs_hash for ipfs_hash in self.data.keys() if not self.data[ipfs_hash].associated_assets}
        for hash in stale_hashes:
            self.remove_ipfs_info(hash)
        self.logger.info(f'pruned {len(stale_hashes)} stale ipfs data sets')

    @modifier
    def remove_ipfs_info(self, ipfs_hash: str):
        self.data.pop(ipfs_hash)
        self.remove_ipfs_data(ipfs_hash)

    def remove_ipfs_data(self, ipfs_hash: str):
        ipfs_file = standardize_path(os.path.join(self.raw_ipfs_path, ipfs_hash))
        try:
            os.remove(ipfs_file)
        except (FileNotFoundError, OSError):
            pass

    async def _download_ipfs_data(self, network: Network, ipfs_hash: str):
        ipfs_url = ipfs_explorer_URL(network.config, 'ipfs', ipfs_hash)
        
        async def on_finish(resp: ClientResponse):
            m = self.get_metadata(ipfs_hash) or IPFSMetadata()
            curr_time = int(time.time())
            try:
                resp.raise_for_status()
                # Ensure we aren't appending to something thats already there
                self.remove_ipfs_data(ipfs_hash)
                downloaded_length = 0
                while chunk := await resp.content.read(8192):
                    downloaded_length += len(chunk)
                    if downloaded_length > network.config.MAX_IPFS_DOWNLOAD_SIZE:
                        self.logger.warn(f'oversized ipfs data for {ipfs_hash}')
                        m.over_sized = True
                        m.known_size = downloaded_length
                        self.remove_ipfs_data(ipfs_hash)
                        break
                    self._append_bytes_to_raw_ipfs_file(ipfs_hash, chunk)
                else:
                    self.logger.info(f'successfully downloaded ipfs data for {ipfs_hash}')
                    m.known_size = downloaded_length
                    m.is_client_side = True
                    util.trigger_callback('ipfs_download', ipfs_hash)
            except ClientResponseError as e:
                self.logger.warn(f'failed to download ipfs data for {ipfs_hash}: {str(e)}')
            finally:
                self._ipfs_download_current.discard(ipfs_hash)
                resp.close()
                m.last_attemped_query = curr_time
                self.data[ipfs_hash] = m

        # Rate limit ourselves :)
        async with self._ipfs_lookup_semaphore:
            await asyncio.sleep(0.25)
            self.logger.info(f'downloading ipfs data for {ipfs_hash}')
            await Network.async_send_http_on_proxy('get', ipfs_url, on_finish=on_finish, timeout=60)

    async def _download_ipfs_information(self, network: Network, ipfs_hash: str):
        ipfs_url = ipfs_explorer_URL(network.config, 'ipfs', ipfs_hash)

        async def on_finish(resp: ClientResponse):
            m = self.get_metadata(ipfs_hash) or IPFSMetadata()
            curr_time = int(time.time())
            try:
                resp.raise_for_status()
                m.known_mime = resp.content_type
                m.known_size = resp.content_length
                m.info_lookup_successful = True
                self.logger.info(f'downloaded information for ipfs {ipfs_hash}: {resp.content_type} {resp.content_length}')
                self._ipfs_lookup_current.discard(ipfs_hash)
                await self.maybe_download_data_for_ipfs_hash(network, ipfs_hash)
            except ClientResponseError as e:
                self.logger.warn(f'failed to download information for ipfs {ipfs_hash}: {str(e)}')
            finally:
                self._ipfs_lookup_current.discard(ipfs_hash)
                resp.close()
                m.last_attemped_query = curr_time
                self.data[ipfs_hash] = m
                util.trigger_callback('ipfs_download', ipfs_hash)

        # Rate limit ourselves :)
        async with self._ipfs_lookup_semaphore:
            await asyncio.sleep(0.25)
            self.logger.info(f'looking up ipfs information {ipfs_hash}')
            await Network.async_send_http_on_proxy('head', ipfs_url, on_finish=on_finish, timeout=30)

    async def maybe_download_data_for_ipfs_hash(self, network: 'Network', ipfs_hash: str):
        assert isinstance(ipfs_hash, str)
        if not network:
            return
        raw_hash = base_decode(ipfs_hash, base=58)
        if len(raw_hash) != 34 or raw_hash[:2] != b'\x12\x20':
            raise ValueError(f'Invalid ipfs hash: {ipfs_hash}')
        if not network.config.DOWNLOAD_IPFS: return
        with self.lock:
            m = self.get_metadata(ipfs_hash)
            # get info calls this
            if ipfs_hash in self._ipfs_lookup_current:
                return
            if ipfs_hash in self._ipfs_download_current:
                return
            if m and not m.is_client_side and is_mime_viewable(m.known_mime) and (m.known_size is None or m.known_size < network.config.MAX_IPFS_DOWNLOAD_SIZE):
                self._ipfs_download_current.add(ipfs_hash)
                await network.taskgroup.spawn(self._download_ipfs_data(network, ipfs_hash))

    async def maybe_get_info_for_ipfs_hash(self, network: 'Network', ipfs_hash: str, asset: str):
        assert isinstance(ipfs_hash, str)
        assert isinstance(asset, str)
        if not network:
            return
        raw_hash = base_decode(ipfs_hash, base=58)
        if len(raw_hash) != 34 or raw_hash[:2] != b'\x12\x20':
            raise ValueError(f'Invalid ipfs hash: {ipfs_hash}')
        self.associate_asset_with_ipfs(ipfs_hash, asset)
        if not network.config.DOWNLOAD_IPFS: return
        with self.lock:
            m = self.get_metadata(ipfs_hash)
            if m.info_lookup_successful:
                return
            if ipfs_hash in self._ipfs_lookup_current:
                return
            self._ipfs_lookup_current.add(ipfs_hash)
            util.trigger_callback('ipfs_download', ipfs_hash)
            await network.taskgroup.spawn(self._download_ipfs_information(network, ipfs_hash))

    @event_listener
    async def on_event_adb_added_verified_asset_metadata(self, adb: 'AddressSynchronizer', asset):
        metadata = adb.db.get_verified_asset_metadata(asset)
        if metadata and metadata.is_associated_data_ipfs():
            await self.maybe_get_info_for_ipfs_hash(adb.network, metadata.associated_data_as_ipfs(), asset)

    @event_listener
    async def on_event_adb_added_unconfirmed_asset_metadata(self, adb: 'AddressSynchronizer', asset):
        metadata_tup = adb.unconfirmed_asset_metadata.get(asset, None)
        if metadata_tup:
            metadata = metadata_tup[0]
            if metadata.is_associated_data_ipfs():
                await self.maybe_get_info_for_ipfs_hash(adb.network, metadata.associated_data_as_ipfs(), asset)

    @event_listener
    def on_event_ipfs_hash_dissociate_asset(self, ipfs_hash: str, asset: str):
        self.dissociate_asset_with_ipfs(ipfs_hash, asset)

    @modifier
    def dissociate_asset_with_ipfs(self, ipfs_hash: str, asset: str):
        m = self.data.get(ipfs_hash, None)
        if m:
            m.associated_assets.discard(asset)

    @modifier
    def associate_asset_with_ipfs(self, ipfs_hash: str, asset: str):
        m = self.data.get(ipfs_hash, None)
        if m is None:
            m = IPFSMetadata(associated_assets={asset})
            self.data[ipfs_hash] = m
        else:
            m.associated_assets.add(asset)

    @locked
    def get_metadata(self, ipfs_hash: str):
        return self.data.get(ipfs_hash, None)

    @locked
    def get_text_for_ipfs_str(self, ipfs_hash: str):
        m = self.data.get(ipfs_hash, None)
        if m is None:
            return (None, ) * 2
        if ipfs_hash in self._ipfs_lookup_current:
            return ('Loading...', ) * 2
        return m.known_mime, human_readable_size(m.known_size, greater_than=m.over_sized)

    @locked
    def get_resource_path_for_ipfs_str(self, ipfs_hash: str):
        m = self.data.get(ipfs_hash, None)
        if m is None or not m.is_client_side:
            return None, None
        path = standardize_path(os.path.join(self.raw_ipfs_path, ipfs_hash))
        if not os.path.exists(path):
            return None, None
        return path, m.known_mime
