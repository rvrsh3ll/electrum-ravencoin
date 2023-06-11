import attr
import re
import hashlib

from enum import Enum
from typing import Optional, Sequence, Mapping, Union, TYPE_CHECKING

from .bitcoin import address_to_script, construct_script, int_to_hex, opcodes, COIN, base_decode, base_encode
from .i18n import _

from .transaction import PartialTxOutput, MalformedBitcoinScript, script_GetOp
from .json_db import StoredObject

# https://github.com/RavenProject/Ravencoin/blob/master/src/assets/assets.cpp

MAX_NAME_LENGTH = 32
MAX_CHANNEL_NAME_LENGTH = 12
MIN_ASSET_LENGTH = 3

DEFAULT_ASSET_AMOUNT_MAX = 21_000_000_000
UNIQUE_ASSET_AMOUNT_MAX = 1
QUALIFIER_ASSET_AMOUNT_MAX = 10

RVN_ASSET_PREFIX = b'rvn'
RVN_ASSET_TYPE_CREATE = b'q'
RVN_ASSET_TYPE_CREATE_INT = RVN_ASSET_TYPE_CREATE[0]
RVN_ASSET_TYPE_OWNER = b'o'
RVN_ASSET_TYPE_OWNER_INT = RVN_ASSET_TYPE_OWNER[0]
RVN_ASSET_TYPE_TRANSFER = b't'
RVN_ASSET_TYPE_TRANSFER_INT = RVN_ASSET_TYPE_TRANSFER[0]

ASSET_OWNER_IDENTIFIER = '!'

_ROOT_NAME_CHARACTERS = r'^[A-Z0-9._]{3,}$'
_SUB_NAME_CHARACTERS = r'^[A-Z0-9._]+$'
_UNIQUE_TAG_CHARACTERS = r'^[-A-Za-z0-9@$%&*()[\]{}_.?:]+$'
_MSG_CHANNEL_TAG_CHARACTERS = r'^[A-Za-z0-9_]+$'
_QUALIFIER_NAME_CHARACTERS = r'#[A-Z0-9._]{3,}$'
_SUB_QUALIFIER_NAME_CHARACTERS = r'#[A-Z0-9._]+$'
_RESTRICTED_NAME_CHARACTERS = r'$[A-Z0-9._]{3,}$'

_DOUBLE_PUNCTUATION = r'^.*[._]{2,}.*$'
_LEADING_PUNCTUATION = r'^[._].*$'
_TRAILING_PUNCTUATION = r'^.*[._]$'
_QUALIFIER_LEADING_PUNCTUATION = r'^[#$][._].*$'

_SUB_NAME_DELIMITER = '/'
_UNIQUE_TAG_DELIMITER = '#'
_MSG_CHANNEL_DELIMITER = '~'
_RESTRICTED_TAG_DELIMITER = '$'
_QUALIFIER_TAG_DELIMITER = '#'

_UNIQUE_INDICATOR = r'(^[^^~#!]+#[^~#!\/]+$)'
_MSG_CHANNEL_INDICATOR = r'(^[^^~#!]+~[^~#!\/]+$)'
_OWNER_INDICATOR = r'(^[^^~#!]+!$)'
_QUALIFIER_INDICATOR = r'^[#][A-Z0-9._]{3,}$'
_SUB_QUALIFIER_INDICATOR = r'^#[A-Z0-9._]+\/#[A-Z0-9._]+$'
_RESTRICTED_INDICATOR = r'^[$][A-Z0-9._]{3,}$'

_BAD_NAMES = '^RVN$|^RAVEN$|^RAVENCOIN$|^RVNS$|^RAVENS$|^RAVENCOINS$|^#RVN$|^#RAVEN$|^#RAVENCOIN$|^#RVNS$|^#RAVENS$|^#RAVENCOINS$'

def _isMatchAny(symbol: str, badMatches: Sequence[str]) -> bool:
    return any((re.match(x, symbol) for x in badMatches))

def _isRootNameValid(symbol: str) -> bool:
    return re.match(_ROOT_NAME_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _LEADING_PUNCTUATION, _TRAILING_PUNCTUATION, _BAD_NAMES])

def _isQualifierNameValid(symbol: str) -> bool:
    return re.match(_QUALIFIER_NAME_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _QUALIFIER_LEADING_PUNCTUATION, _TRAILING_PUNCTUATION, _BAD_NAMES])

def _isRestrictedNameValid(symbol: str) -> bool:
    return re.match(_RESTRICTED_NAME_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _LEADING_PUNCTUATION, _TRAILING_PUNCTUATION, _BAD_NAMES])

def _isSubQualifierNameValid(symbol: str) -> bool:
    return re.match(_SUB_QUALIFIER_NAME_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _LEADING_PUNCTUATION, _TRAILING_PUNCTUATION])

def _isSubNameValid(symbol: str) -> bool:
    return re.match(_SUB_NAME_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _LEADING_PUNCTUATION, _TRAILING_PUNCTUATION])

def _isUniqueTagValid(symbol: str) -> bool:
    return re.match(_UNIQUE_TAG_CHARACTERS, symbol)

def _isMsgChannelTagValid(symbol: str) -> bool:
    return re.match(_MSG_CHANNEL_TAG_CHARACTERS, symbol) and \
        not _isMatchAny(symbol, [_DOUBLE_PUNCTUATION, _LEADING_PUNCTUATION, _TRAILING_PUNCTUATION])

def _isNameValidBeforeTag(symbol: str) -> bool:
    parts = symbol.split(_SUB_NAME_DELIMITER)
    for i, part in enumerate(parts):
        if i == 0:
            if not _isRootNameValid(part): return False
        else:
            if not _isSubNameValid(part): return False
    return True

def _isQualifierNameValidBeforeTag(symbol: str) -> bool:
    parts = symbol.split(_SUB_NAME_DELIMITER)
    if not _isQualifierNameValid(parts[0]): return False
    if len(parts) > 2: return False
    for part in parts[1:]:
        if not _isSubQualifierNameValid(part): return False

    return True

def _isAssetNameASubAsset(asset: str) -> bool:
    parts = asset.split(_SUB_NAME_DELIMITER)
    if not _isRootNameValid(parts[0]): return False
    return len(parts) > 1

def _isAssetNameASubQualifier(asset: str) -> bool:
    parts = asset.split(_SUB_NAME_DELIMITER)
    if not _isQualifierNameValid(parts[0]): return False
    return len(parts) > 1

class AssetType(Enum):
    ROOT = 1
    SUB = 2
    MSG_CHANNEL = 3
    OWNER = 4
    UNIQUE = 5
    QUALIFIER = 6
    SUB_QUALIFIER = 7
    RESTRICTED = 8

class AssetException(Exception):
    pass

def get_error_for_asset_typed(asset: str, asset_type: AssetType) -> Optional[str]:
    if asset_type == AssetType.SUB and _SUB_NAME_DELIMITER not in asset:
        return _('Not a sub asset.')
    if asset_type == AssetType.ROOT or asset_type == AssetType.SUB:
        if len(asset) > MAX_NAME_LENGTH - 1:
            return _('Name is greater than max length of {}.'.format(MAX_NAME_LENGTH - 1))
        
        if not _isAssetNameASubAsset(asset) and len(asset) < MIN_ASSET_LENGTH:
            return _('Name must contain at least {} characters.'.format(MIN_ASSET_LENGTH))

        valid = _isNameValidBeforeTag(asset)
        if not valid and _isAssetNameASubAsset(asset) and len(asset) < MIN_ASSET_LENGTH:
            return _('Name must have at least {} characters (Valid characters are: A-Z 0-9 _ .)'.format(MIN_ASSET_LENGTH))
        
        if not valid:
            return _('Name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can\'t be the first or last characters)')

        return None
    else:
        if len(asset) > MAX_NAME_LENGTH:
            return _('Name is greater than max length of {}.'.format(MAX_NAME_LENGTH))

        if asset_type == AssetType.UNIQUE:
            parts = asset.split(_UNIQUE_TAG_DELIMITER)
            if len(parts) == 1:
                return _('Not a unique tag.')
            if not _isNameValidBeforeTag(parts[0]) or not _isUniqueTagValid(parts[-1]):
                return _('Unique name contains invalid characters (Valid characters are: A-Z a-z 0-9 @ $ % & * ( ) [ ] { } _ . ? : -)')
        elif asset_type == AssetType.MSG_CHANNEL:
            parts = asset.split(_MSG_CHANNEL_DELIMITER)
            if len(parts) == 1:
                return _('Not a message channel.')
            if len(parts[-1]) > MAX_CHANNEL_NAME_LENGTH:
                return _('Channel name is greater than max length of {}.'.format(MAX_CHANNEL_NAME_LENGTH))
            if not _isNameValidBeforeTag(parts[0]) or not _isMsgChannelTagValid(parts[-1]):
                return _('Message Channel name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can\'t be the first or last characters)')
        elif asset_type == AssetType.OWNER:
            if not _isNameValidBeforeTag(asset[:-1]):
                return _('Owner name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can\'t be the first or last characters)')
        elif asset_type == AssetType.QUALIFIER or asset_type == AssetType.SUB_QUALIFIER:
            if not _isQualifierNameValidBeforeTag(asset):
                return _('Qualifier name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (# must be the first character, _ . special characters can\'t be the first or last characters)')
        elif asset_type == AssetType.RESTRICTED:
            if not _isRestrictedNameValid(asset):
                return _('Restricted name contains invalid characters (Valid characters are: A-Z 0-9 _ .) ($ must be the first character, _ . special characters can\'t be the first or last characters)')
        else:
            return _('Unknown asset type.')
        return None

def get_error_for_asset_name(asset: str) -> Optional[str]:
    if len(asset) > 40: return _('Asset is too long')

    if re.match(_UNIQUE_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.UNIQUE)
    elif re.match(_MSG_CHANNEL_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.MSG_CHANNEL)
    elif re.match(_OWNER_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.OWNER)
    elif re.match(_QUALIFIER_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.QUALIFIER)
    elif re.match(_SUB_QUALIFIER_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.SUB_QUALIFIER)
    elif re.match(_RESTRICTED_INDICATOR, asset): return get_error_for_asset_typed(asset, AssetType.RESTRICTED)
    else: return get_error_for_asset_typed(asset, AssetType.SUB if _isAssetNameASubAsset(asset) else AssetType.ROOT)

def generate_create_script(address: str, asset: str, amount: int, divisions: int, reissuable: bool, associated_data: Optional[bytes]) -> 'PartialTxOutput':
    if get_error_for_asset_name(asset):
        raise AssetException('Bad asset')
    if not amount > 0 or amount > DEFAULT_ASSET_AMOUNT_MAX * COIN:
        raise AssetException('Bad amount')
    if divisions < 0 or divisions > 8:
        raise AssetException('Bad divisions')
    if associated_data and len(associated_data) != 34:
        raise AssetException('Bad data')

    asset_data = (f'{RVN_ASSET_PREFIX.hex()}{RVN_ASSET_TYPE_CREATE.hex()}'
                  f'{int_to_hex(len(asset))}{asset.encode().hex()}'
                  f'{int_to_hex(amount, 8)}{int_to_hex(divisions)}'
                  f"{'01' if reissuable else '00'}{'01' if associated_data else '00'}"
                  f'{associated_data.hex() if associated_data else ""}')
    asset_script = construct_script([opcodes.OP_ASSET, asset_data, opcodes.OP_DROP])
    base_script = address_to_script(address)
    return base_script + asset_script

def generate_owner_script(address: str, asset: str) -> 'PartialTxOutput':
    if asset[-1] != ASSET_OWNER_IDENTIFIER:
        asset += ASSET_OWNER_IDENTIFIER
    if get_error_for_asset_name(asset):
        raise AssetException('Bad asset')
    
    asset_data = (f'{RVN_ASSET_PREFIX.hex()}{RVN_ASSET_TYPE_OWNER.hex()}'
                  f'{int_to_hex(len(asset))}{asset.encode().hex()}')
    
    asset_script = construct_script([opcodes.OP_ASSET, asset_data, opcodes.OP_DROP])
    base_script = address_to_script(address)
    return base_script + asset_script

def _associated_data_converter(input):
    if not input:
        return None
    if isinstance(input, str) and len(input) == 68:
        input = bytes.fromhex(input)
    if isinstance(input, bytes):
        if len(input) != 34:
            raise ValueError(f'{input=} is not 34 bytes')
        return input
    result = base_decode(input, base=58)
    if len(result) != 34:
        raise ValueError(f'{input=} decoded is not 34 bytes')
    return result


@attr.s
class AssetMemo:
    data = attr.ib(type=bytes, converter=_associated_data_converter)
    timestamp = attr.ib(default=None, type=int)

    def hex(self) -> str:
        return f'{self.data.hex()}{int_to_hex(self.timestamp, 8) if self.timestamp else ""}'

def _asset_portion_of_transfer_script(asset: str, amount: int, *, memo: AssetMemo = None) -> str:
    asset_data = (f'{RVN_ASSET_PREFIX.hex()}{RVN_ASSET_TYPE_TRANSFER.hex()}'
                  f'{int_to_hex(len(asset))}{asset.encode().hex()}'
                  f'{int_to_hex(amount, 8)}{memo.hex() if memo else ""}')
    asset_script = construct_script([opcodes.OP_ASSET, asset_data, opcodes.OP_DROP])
    return asset_script

def extra_size_for_asset_transfer(asset: str):
    return len(_asset_portion_of_transfer_script(asset, 0)) // 2

def generate_transfer_script(asset: str, amount: int, base_script: str):
    return base_script + _asset_portion_of_transfer_script(asset, amount)
    
def _validate_sats(instance, attribute, value):
    if value <= 0:
        raise ValueError('sats must be greater than 0!')

def _validate_divisions(instance, attribute, value):
    if value < 0 or value > 8:
        raise ValueError('divisions must be 0-8!')

@attr.s
class AssetMetadata(StoredObject):
    sats_in_circulation = attr.ib(type=int, validator=_validate_sats)
    divisions = attr.ib(type=int, validator=_validate_divisions)
    reissuable = attr.ib(type=bool)
    associated_data = attr.ib(default=None, type=bytes, converter=_associated_data_converter)

    def associated_data_as_ipfs(self) -> Optional[str]:
        if not self.associated_data:
            return None
        return base_encode(self.associated_data, base=58)
    
    def status(self) -> Optional[str]:
        """ Returns the asset status as a hex string """
        h = ''.join([str(self.sats_in_circulation), 
                     str(self.divisions),
                     str(self.reissuable),
                     str(self.associated_data is not None)])
        if self.associated_data is not None:
            h += self.associated_data_as_ipfs()

        return hashlib.sha256(h.encode('ascii')).digest().hex()

class AssetVoutType(Enum):
    NONE = 1
    TRANSFER = 2
    CREATE = 3
    OWNER = 4
    REISSUE = 5

class BaseAssetVoutInformation():
    asset = None
    amount: Optional[int] = None

    def __init__(self, type_: AssetVoutType):
        self._type = type_

    def get_type(self):
        return self._type
    
    def is_transferable(self):
        return self._type in (AssetVoutType.CREATE, AssetVoutType.OWNER, AssetVoutType.TRANSFER, AssetVoutType.REISSUE)

    def is_deterministic(self):
        return False

class NoAssetVoutInformation(BaseAssetVoutInformation):
    def __init__(self):
        BaseAssetVoutInformation.__init__(self, AssetVoutType.NONE)

class MetadataAssetVoutInformation(BaseAssetVoutInformation):
    def __init__(self, type_: AssetVoutType, asset: str, amount: int, divisions: int, reissuable: bool, associated_data: Optional[bytes]):
        BaseAssetVoutInformation.__init__(self, type_)
        self.asset = asset
        self.amount = amount
        self.divisions = divisions
        self.reissuable = reissuable
        self.associated_data = associated_data

class OwnerAssetVoutInformation(BaseAssetVoutInformation):
    def __init__(self, asset: str):
        BaseAssetVoutInformation.__init__(self, AssetVoutType.OWNER)
        self.asset = asset
        self.amount = COIN

def get_asset_info_from_script(script: bytes) -> BaseAssetVoutInformation:
    try:
        decoded = [x for x in script_GetOp(script)]
    except MalformedBitcoinScript:
        return None

    for i, (op, _, index) in enumerate(decoded):
        if op == opcodes.OP_ASSET:
            if i == 0:
                pass
            else:
                asset_portion = script[index:]
                asset_prefix_position = asset_portion.find(RVN_ASSET_PREFIX)
                if asset_prefix_position < 0: break
                if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3: break
                vout_type = asset_portion[len(RVN_ASSET_PREFIX) + 1]
                if vout_type == RVN_ASSET_TYPE_CREATE_INT:
                    asset_vout_type = AssetVoutType.CREATE
                elif vout_type == RVN_ASSET_TYPE_OWNER_INT:
                    asset_vout_type = AssetVoutType.OWNER
                else: break

                asset_length = asset_portion[len(RVN_ASSET_PREFIX) + 2]
                if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3 + asset_length: break

                asset = asset_portion[len(RVN_ASSET_PREFIX) + 3:len(RVN_ASSET_PREFIX) + 3 + asset_length].decode()
                if asset_vout_type == AssetVoutType.OWNER:
                    return OwnerAssetVoutInformation(asset)

                if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3 + 8 + asset_length: break
                asset_amount = int.from_bytes(asset_portion[len(RVN_ASSET_PREFIX) + 3 + asset_length:len(RVN_ASSET_PREFIX) + 3 + 8 + asset_length], 'little')

                if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3 + 8 + 2 + asset_length: break
                divisions = asset_portion[len(RVN_ASSET_PREFIX) + 3 + 8 + asset_length]
                reissuable = bool(asset_portion[len(RVN_ASSET_PREFIX) + 3 + 8 + 1 + asset_length])

                if asset_vout_type == AssetVoutType.CREATE:
                    if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3 + 8 + 3 + asset_length: break
                    has_associated_data = asset_portion[len(RVN_ASSET_PREFIX) + 3 + 8 + 2 + asset_length]
                    if has_associated_data:
                        if len(asset_portion) < len(RVN_ASSET_PREFIX) + 3 + 8 + 4 + 34 + asset_length: break
                        associated_data = asset_portion[len(RVN_ASSET_PREFIX) + 3 + 8 + 3 + asset_length:len(RVN_ASSET_PREFIX) + 3 + 8 + 3 + 34 + asset_length]
                        return MetadataAssetVoutInformation(asset_vout_type, asset, asset_amount, divisions, reissuable, associated_data)
                    else:
                        return MetadataAssetVoutInformation(asset_vout_type, asset, asset_amount, divisions, reissuable, None)

                break

    return NoAssetVoutInformation()
