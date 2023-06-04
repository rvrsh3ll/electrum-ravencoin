import re

from enum import Enum
from typing import Optional, Sequence

from .i18n import _

# https://github.com/RavenProject/Ravencoin/blob/master/src/assets/assets.cpp

MAX_NAME_LENGTH = 32
MAX_CHANNEL_NAME_LENGTH = 12
MIN_ASSET_LENGTH = 3

DEFAULT_ASSET_AMOUNT_MAX = 21_000_000_000
UNIQUE_ASSET_AMOUNT_MAX = 1
QUALIFIER_ASSET_AMOUNT_MAX = 10

_ROOT_NAME_CHARACTERS = r'^[A-Z0-9._]{3,}$'
_SUB_NAME_CHARACTERS = r'^[A-Z0-9._]+$'
_UNIQUE_TAG_CHARACTERS = r'^[-A-Za-z0-9@$%&*()[\]{}_.?:]+$'
_MSG_CHANNEL_TAG_CHARACTERS = r'^[A-Za-z0-9_]+$'
_QUALIFIER_NAME_CHARACTERS = r'#[A-Z0-9._]{3,}$'
_SUB_QUALIFIER_NAME_CHARACTERS = r'#[A-Z0-9._]+$'
_RESTRICTED_NAME_CHARACTERS = r'\$[A-Z0-9._]{3,}$'

_DOUBLE_PUNCTUATION = r'^.*[._]{2,}.*$'
_LEADING_PUNCTUATION = r'^[._].*$'
_TRAILING_PUNCTUATION = r'^.*[._]$'
_QUALIFIER_LEADING_PUNCTUATION = r'^[#\$][._].*$'

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
_RESTRICTED_INDICATOR = r'^[\$][A-Z0-9._]{3,}$'

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
                return _('Unique name contains invalid characters (Valid characters are: A-Z a-z 0-9 @ \$ % & * ( ) [ ] { } _ . ? : -)')
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
                return _('Restricted name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (\$ must be the first character, _ . special characters can\'t be the first or last characters)')
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
