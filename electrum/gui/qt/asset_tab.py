import asyncio
import enum
import math
import hashlib
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Sequence, List, Callable, Any, Mapping, Tuple
from urllib.parse import urlparse

from PyQt5.QtGui import QFontMetrics, QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import pyqtSignal, QPoint, Qt, QItemSelectionModel
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QGridLayout, QSizePolicy, QLineEdit, QCheckBox, QSplitter, QScrollArea,
                             QHBoxLayout, QCompleter, QWidget, QFrame, QPushButton, QTabWidget, QAbstractItemView,
                             QTextEdit, QComboBox)

from electrum import util, paymentrequest, constants
from electrum import lnutil
from electrum.asset import (get_error_for_asset_typed, AssetType, DEFAULT_ASSET_AMOUNT_MAX, QUALIFIER_ASSET_AMOUNT_MAX, generate_create_script, generate_owner_script, AssetMetadata,
                            )
from electrum.bitcoin import base_decode, BaseDecodeError, COIN, is_address, base_encode
from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.util import (get_asyncio_loop, FailedToParsePaymentIdentifier, format_satoshis_plain, profiler,
                           InvalidBitcoinURI, maybe_extract_lightning_payment_identifier, NotEnoughFunds,
                           NoDynamicFeeEstimates, InvoiceError, parse_max_spend, DECIMAL_POINT, ipfs_explorer_URL)
from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.invoices import PR_PAID, Invoice, PR_BROADCASTING, PR_BROADCAST
from electrum.transaction import Transaction, PartialTxInput, PartialTransaction, PartialTxOutput
from electrum.network import TxBroadcastError, BestEffortRequestFailed, UntrustedServerReturnedError
from electrum.logging import Logger
from electrum.lnaddr import lndecode, LnInvoiceException
from electrum.lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, LNURL6Data

from electrum.ipfs_db import IPFSDB

from .amountedit import AmountEdit, BTCAmountEdit, SizedFreezableLineEdit
from .util import WaitingDialog, HelpLabel, MessageBoxMixin, char_width_in_lineedit, GenericInputHandler, EnterButton, ColorScheme, HelpButton
from .util import QHSeperationLine, get_iconname_qrcode, read_QIcon, MONOSPACE_FONT, ChoicesLayout, ValidatedDelayedCallbackEditor, font_height
from .confirm_tx_dialog import ConfirmTxDialog
from .my_treeview import MyTreeView

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from aiohttp import ClientResponse


_VIEWABLE_MIMES = ('image/jpeg', 'image/png', 'image/gif', 'image/tiff', 'image/webp', 'image/avif',
                    'text/plain', 'application/json')

def human_readable_size(size, decimal_places=3):
    if not isinstance(size, int):
        return _('Unknown')
    for unit in ['Bytes','KiB','MiB','GiB','TiB']:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.{decimal_places}g} {unit}"

class OnlyNumberAmountEdit(AmountEdit):
    def __init__(self, asset_name: Callable[[], str], divisions: int, max_amount: int, *, parent=None, min_amount=0, callback=None):
        AmountEdit.__init__(self, asset_name, True, parent, max_amount=max_amount, min_amount=min_amount, callback=callback)
        self.divisions = divisions

    def decimal_point(self):
        return self.divisions
    
    def max_precision(self):
        return 8

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.setText('')
        return super().numbify()

class AssetAmountEdit(OnlyNumberAmountEdit):
    def _get_amount_from_text(self, text):
        # returns amt in satoshis
        try:
            text = text.replace(DECIMAL_POINT, '.')
            x = Decimal(text)
        except Exception:
            return None
        # scale it to max allowed precision, make it an int
        power = pow(10, self.max_precision())
        max_prec_amount = int(power * x)
        # if the max precision is simply what unit conversion allows, just return
        return max_prec_amount
    
    def _get_text_from_amount(self, amount_sat):
        text = format_satoshis_plain(amount_sat, decimal_point=self.max_precision())
        text = text.replace('.', DECIMAL_POINT)
        return text
        
class AssetList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()
        BALANCE = enum.auto()

    headers = {
        Columns.ASSET: _('Asset'),
        Columns.BALANCE: _('Balance'),
    }
    filter_columns = [Columns.ASSET]
    stretch_column = Columns.ASSET

    ROLE_ASSET_STR = Qt.UserRole + 1000
    key_role = ROLE_ASSET_STR

    def __init__(self, parent: 'ViewAssetPanel'):
        super().__init__(
            main_window=parent.parent.window,
            stretch_column=self.stretch_column,
        )
        self.parent = parent
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.last_selected_asset = None
        self.current_assets = []

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                self.parent.metadata_viewer.update_asset_trigger.emit(None)
                return
            first_row = min(rows)
            self.last_selected_asset = asset = self.model().index(first_row, self.Columns.ASSET).data(self.ROLE_ASSET_STR)
            self.parent.metadata_viewer.update_asset_trigger.emit(asset)

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        watching_assets = self.wallet.get_assets_to_watch()
        new_assets = [(asset, (metadata[0].sats_in_circulation, metadata[1]) if ((metadata := self.wallet.get_asset_metadata(asset)) is not None) else None) for asset in watching_assets]
        if self.current_assets == new_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (asset, data) in enumerate(new_assets):
            labels = [""] * len(self.Columns)
            labels[self.Columns.ASSET] = asset
            if self.wallet.do_we_own_this_asset(asset):
                amount = sum(self.wallet.get_balance(asset_aware=True)[asset])
                labels[self.Columns.BALANCE] = self.main_window.config.format_amount(amount, whitespaces=True, precision=8)                
            asset_item = [QStandardItem(x) for x in labels]
            if not self.wallet.do_we_own_this_asset(asset):
                asset_item[self.Columns.BALANCE] = QStandardItem(read_QIcon('eye1.png'), labels[self.Columns.BALANCE])
            self.set_editability(asset_item)
            asset_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            asset_item[self.Columns.ASSET].setFont(QFont(MONOSPACE_FONT))
            asset_item[self.Columns.BALANCE].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, asset_item)
            self.refresh_row(asset, data, idx)
            if asset == self.last_selected_asset:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_assets = new_assets
        self.filter()

    def refresh_row(self, key, data, row):
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        
        color = self._default_bg_brush

        if data is None:
            tooltip = _('No asset metadata avaliable')
            color = ColorScheme.RED.as_color(True)
        else:
            total_sats, kind = data
            tooltip = _('{} total coins of {} exist').format(format_satoshis_plain(total_sats, decimal_point=8), key)
            if kind == METADATA_UNCONFIRMED:
                tooltip += ' ' + _('(this metadata is not yet confirmed)')
            elif kind == METADATA_UNVERIFIED:
                tooltip += ' ' + _('(this metadata was not able to be verified)')

        if not self.wallet.do_we_own_this_asset(key):
            tooltip += ' ' + _('(This is a watch-only asset)')            

        for col in asset_item:
            col.setBackground(color)
            col.setToolTip(tooltip)
        
class MetadataInfo(QWidget):
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self)

        self.window = window

        vbox = QVBoxLayout(self)

        self.header = QLabel()
        self.header.setAlignment(Qt.AlignCenter)
        header_help = HelpButton(_('Asset metadata is validated client-side, however, servers may broadcast old data or make-up data in the mempool.' +
                                   ' Additionally, the total created supply cannot be completely validated client-side.'))

        header_layout = QHBoxLayout()
        header_layout.addWidget(self.header)
        header_layout.addWidget(header_help)

        asset_label = QLabel(_('Asset: '))
        self.asset_text = QLabel()
        type_label = QLabel(_('Type: '))
        self.type_text = QLabel()

        asset_layout = QHBoxLayout()
        type_layout = QHBoxLayout()
        asset_layout.addWidget(asset_label)
        asset_layout.addWidget(self.asset_text, 1, Qt.AlignLeft)
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.type_text, 1, Qt.AlignLeft)

        divisions_message = _('Asset Divisions') + '\n\n' \
                            + _('Asset divisions are a number from 0 to 8 and denote how many digits past the decimal point can be used. Once an asset is issued, you cannot decrease this number.')
        divisions_label = HelpLabel(_('Divisions: '), divisions_message)

        self.divisions_text = QLabel()

        reissuable_message = _('Asset Divisions') + '\n\n' \
                            + _('Asset divisions are a number from 0 to 8 and denote how many digits past the decimal point can be used. Once an asset is issued, you cannot decrease this number.')
        reissuable_label = HelpLabel(_('Reissuable: '), reissuable_message)
        self.reissuable_text = QLabel()

        basic_info_layout = QHBoxLayout()
        basic_info_layout.addWidget(divisions_label)
        basic_info_layout.addWidget(self.divisions_text, 1, Qt.AlignLeft)
        basic_info_layout.addWidget(reissuable_label)
        basic_info_layout.addWidget(self.reissuable_text, 1, Qt.AlignLeft)
        basic_info_layout.setSpacing(5)

        associated_data_type_label = QLabel(_('Associated Data: '))
        self.associated_data_type_text = QLabel()
        associated_data_type_layout = QHBoxLayout()
        associated_data_type_layout.addWidget(associated_data_type_label)
        associated_data_type_layout.addWidget(self.associated_data_type_text, 1, Qt.AlignLeft)

        self.associated_data_text = QTextEdit()
        self.associated_data_text.setReadOnly(True)
        self.associated_data_text.setFixedHeight(math.floor(font_height() * 1.7))
        self.associated_data_text.setAlignment(Qt.AlignVCenter)

        associated_data_info_layout = QVBoxLayout()
        associated_data_info_layout.addLayout(associated_data_type_layout)
        associated_data_info_layout.addWidget(self.associated_data_text)

        self.associated_data_view_seperator = QHSeperationLine()
        predicted_mime_type_layout = QHBoxLayout()
        self.predicted_mime_type_label = QLabel(_('Predicted MIME Type: '))
        self.predicted_mime_type_text = QLabel()
        predicted_size_layout = QHBoxLayout()
        self.predicted_size_label = QLabel(_('Predicted Size: '))
        self.predicted_size_text = QLabel()
        predicted_mime_type_layout.addWidget(self.predicted_mime_type_label)
        predicted_mime_type_layout.addWidget(self.predicted_mime_type_text, 1, Qt.AlignLeft)
        predicted_size_layout.addWidget(self.predicted_size_label)
        predicted_size_layout.addWidget(self.predicted_size_text, 1, Qt.AlignLeft)

        associated_data_view_layout = QVBoxLayout()
        associated_data_view_layout.addWidget(self.associated_data_view_seperator)
        associated_data_view_layout.addLayout(predicted_mime_type_layout)
        associated_data_view_layout.addLayout(predicted_size_layout)

        vbox.addLayout(header_layout)
        vbox.addLayout(asset_layout)
        vbox.addLayout(type_layout)
        vbox.addLayout(basic_info_layout)
        vbox.addLayout(associated_data_info_layout)
        vbox.addLayout(associated_data_view_layout)
        vbox.addWidget(QWidget(), 1)
        self.clear()

        self.current_asset = None

    def update(self, asset: str, type_text: Optional[str], metadata: AssetMetadata):
        self.current_asset = asset
        if type_text:
            header_text = '<h3>{} ({})</h3>'.format(_('Asset Metadata'), type_text)
        else:
            header_text = '<h3>{}</h3>'.format(_('Asset Metadata'))
        self.header.setText(header_text)
        self.asset_text.setText(asset)
        
        if asset[-1] == '!':
            type_text = 'Owner'
        elif '~' in asset:
            type_text = 'Message'
        elif asset[0] == '#':
            type_text = 'Qualifier'
        elif asset[0] == '$':
            type_text = 'Restricted'
        elif '#' in asset:
            type_text = 'Unique'
        else:
            type_text = 'Standard'
        self.type_text.setText(type_text)

        self.divisions_text.setText(str(metadata.divisions))
        self.reissuable_text.setText(str(metadata.reissuable))

        if metadata.associated_data is None:
            self.associated_data_type_text.setText('None')
            self.associated_data_text.setVisible(False)
            for x in [self.predicted_mime_type_label, self.predicted_size_label, self.predicted_mime_type_text, self.predicted_size_text, self.associated_data_view_seperator]:
                x.setVisible(False)
        else:
            self.associated_data_text.setVisible(True)
            for x in [self.predicted_mime_type_label, self.predicted_size_label, self.predicted_mime_type_text, self.predicted_size_text, self.associated_data_view_seperator]:
                x.setVisible(self.window.config.DOWNLOAD_IPFS)
            if metadata.associated_data[:2] == b'\x54\x20':
                self.associated_data_type_text.setText('TXID')
                self.associated_data_text.setText(metadata.associated_data[2:].hex())
            else:
                self.associated_data_type_text.setText('IPFS')
                ipfs_str = base_encode(metadata.associated_data, base=58)
                self.associated_data_text.setText(ipfs_str)
                if self.window.config.DOWNLOAD_IPFS:
                    for x in [self.predicted_mime_type_text, self.predicted_size_text]:
                        x.setText(_('Loading...'))
                    saved_mime_type, saved_bytes = IPFSDB.get_instance().get_metadata(ipfs_str) or (None, None)
                    if saved_mime_type is None or saved_bytes is None:
                        self.window.run_coroutine_from_thread(self.maybe_download_ipfs(asset, ipfs_str, saved_mime_type, saved_bytes), ipfs_str)
                    else:
                        self.predicted_mime_type_text.setText(saved_mime_type)
                        self.predicted_size_text.setText(human_readable_size(saved_bytes))

    def clear(self):
        self.header.setText('<h3>{}</h3>'.format(_('Asset Metadata')))
        for x in [self.asset_text, self.type_text, self.divisions_text, self.reissuable_text, self.associated_data_type_text]:
            x.setText(_('N/A'))

        self.associated_data_text.setText('')

        for x in [self.associated_data_text]:
            x.setVisible(True)

        for x in [self.predicted_mime_type_text, self.predicted_size_text]:
            x.setText(_('N/A'))

        self.update_no_change()

    def update_no_change(self):
        for x in [self.predicted_mime_type_label, self.predicted_size_label, self.predicted_mime_type_text, self.predicted_size_text, self.associated_data_view_seperator]:
            x.setVisible(self.window.config.DOWNLOAD_IPFS and bool(self.associated_data_text.toPlainText()))

    async def maybe_download_ipfs(self, asset: str, ipfs: str, saved_bytes, saved_mime_type):
        if saved_bytes is not None and asset == self.current_asset:
            self.predicted_size_text.setText(human_readable_size(saved_bytes))
        if saved_mime_type:
            if asset == self.current_asset:
                self.predicted_mime_type_text.setText(saved_mime_type)
            return
        ipfs_url = ipfs_explorer_URL(self.window.config, 'ipfs', ipfs)
        async def on_finish(resp: 'ClientResponse'):
            resp.raise_for_status()
            if asset == self.current_asset:
                self.predicted_mime_type_text.setText(resp.content_type or _('Unknown'))
            if saved_bytes:
                IPFSDB.get_instance().add_metadata(ipfs, resp.content_type or None, saved_bytes)
                return
            if resp.content_length:
                content_length = resp.content_length
            else:
                content_length = 0
                while True:
                    chunk = await resp.content.read(1024)
                    if not chunk:
                        break
                    content_length += len(chunk)
            if asset == self.current_asset:
                self.predicted_size_text.setText(human_readable_size(content_length))
            IPFSDB.get_instance().add_metadata(ipfs, resp.content_type or None, content_length)
        try:
            await self.window.network.async_send_http_on_proxy('get', ipfs_url, on_finish=on_finish)
        except Exception as e:
            self.window.logger.error(f'failed to download {ipfs_url=}: {repr(e)}')
            if asset == self.current_asset:
                for x in [self.predicted_mime_type_text, self.predicted_size_text]:
                    x.setText(_('Unknown'))

class MetadataViewer(QFrame):
    update_asset_trigger = pyqtSignal(str)

    def __init__(self, parent: 'ViewAssetPanel'):
        QFrame.__init__(self)
        self.parent = parent
        self.update_asset_trigger.connect(lambda asset: self.update_info(asset))

        self.metadata_info = MetadataInfo(parent.parent.window)

        scroll = QScrollArea()
        scroll.setWidget(self.metadata_info)
        scroll.setWidgetResizable(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

    def update_info(self, asset: str):
        if asset is None:
            self.metadata_info.clear()
            return
        metadata_tup = self.parent.parent.wallet.get_asset_metadata(asset)
        if metadata_tup is None:
            self.metadata_info.clear()
            return
        metadata, metadata_source = metadata_tup
        type_text = None
        if metadata_source == METADATA_UNCONFIRMED:
            type_text = _('UNCONFIRMED')
        elif metadata_source == METADATA_UNVERIFIED:
            type_text = _('NOT VERIFIED!')
        self.metadata_info.update(asset, type_text, metadata)

    def update(self):
        self.metadata_info.update_no_change()
        super().update()

class ViewAssetPanel(QSplitter, Logger):
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.asset_list = AssetList(self)
        self.metadata_viewer = MetadataViewer(self)

        self.asset_list.setMinimumWidth(300)
        self.metadata_viewer.setMinimumWidth(300)

        self.setChildrenCollapsible(False)
        self.addWidget(self.asset_list)
        self.addWidget(self.metadata_viewer)

    def update(self):
        self.asset_list.update()
        self.metadata_viewer.update()
        super().update()

class CreateAssetPanel(QWidget, Logger):
    asset_types = (
            ('Main', AssetType.ROOT, constants.net.BURN_ADDRESSES.IssueAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueAssetBurnAmount),
            ('Sub', AssetType.SUB, constants.net.BURN_ADDRESSES.IssueSubAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueSubAssetBurnAmount),
            ('Unique', AssetType.UNIQUE, constants.net.BURN_ADDRESSES.IssueUniqueAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueUniqueAssetBurnAmount),
            ('Message', AssetType.MSG_CHANNEL, constants.net.BURN_ADDRESSES.IssueMsgChannelAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueMsgChannelAssetBurnAmount),
            ('Qualifier', AssetType.QUALIFIER, constants.net.BURN_ADDRESSES.IssueQualifierAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueQualifierAssetBurnAmount),
            ('Sub Qualifier', AssetType.SUB_QUALIFIER, constants.net.BURN_ADDRESSES.IssueSubQualifierAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueSubQualifierAssetBurnAmount),
            ('Restricted', AssetType.RESTRICTED, constants.net.BURN_ADDRESSES.IssueRestrictedAssetBurnAddress, constants.net.BURN_AMOUNTS.IssueRestrictedAssetBurnAmount),
        )
    
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        #grid.setColumnStretch(10, 1)
        #grid.setRowStretch(4, 1)

        self.asset_is_ok = False
        self.associated_data_is_ok = True
        self.address_is_ok = True
        self.parent_is_ok = True
        self.parent_assets = None

        def clayout_on_edit(clayout: ChoicesLayout):
            self.burn_address = self.asset_types[clayout.selected_index()][2]
            self.burn_amount = self.asset_types[clayout.selected_index()][3]
            self.send_button.setText(_("Pay") + f" {self.burn_amount} RVN...")

            self.amount_e.setAmount(COIN)
            self.divisions_e.setAmount(0)
            self._on_divisions_change(0)
            self.reissuable.setChecked(True)

            asset_type = self.asset_types[clayout.selected_index()]
            if asset_type[1] in (AssetType.ROOT, AssetType.SUB, AssetType.RESTRICTED):
                self.amount_e.max_amount = DEFAULT_ASSET_AMOUNT_MAX * COIN
                self.divisions_e.max_amount = 8
                self.amount_e.setEnabled(True)
                self.divisions_e.setEnabled(True)
                self.reissuable.setEnabled(True)
            elif asset_type[1] in (AssetType.UNIQUE, AssetType.MSG_CHANNEL, AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
                self.amount_e.setEnabled(False)
                self.divisions_e.setEnabled(False)
                self.reissuable.setEnabled(False)
                self.reissuable.setChecked(False)

            if asset_type[1] in (AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
                self.amount_e.setEnabled(True)
                self.amount_e.max_amount = QUALIFIER_ASSET_AMOUNT_MAX * COIN

            if asset_type[1] in (AssetType.MSG_CHANNEL, ):
                self.associated_data_e.line_edit.setText('')
                self.associated_data_e.line_edit.setEnabled(False)
            else:
                self.associated_data_e.line_edit.setEnabled(True)

            self.parent_asset_selector_combo.setVisible(asset_type[1] not in (AssetType.ROOT, AssetType.QUALIFIER))
            if asset_type[1] in (AssetType.SUB, AssetType.UNIQUE, AssetType.MSG_CHANNEL):
                self.update_parent_assets([AssetType.ROOT, AssetType.SUB])
            elif asset_type[1] in (AssetType.SUB_QUALIFIER, ):
                self.update_parent_assets([AssetType.QUALIFIER])
            elif asset_type[1] in (AssetType.RESTRICTED, ):
                self.update_parent_assets([AssetType.ROOT])

            if asset_type[1] in (AssetType.ROOT, AssetType.QUALIFIER):
                self.asset_checker.line_edit.setEnabled(True)
                self.parent_is_ok = True
            else:
                selected_index = self.parent_asset_selector_combo.currentIndex()
                self.parent_is_ok = selected_index > 0 and self.parent_assets[selected_index][1]
                if asset_type[1] == AssetType.RESTRICTED:
                    self.asset_checker.line_edit.setEnabled(False)
                    if selected_index > 0:
                        selected_asset = self.parent_assets[selected_index - 1][0]
                        self.asset_checker.line_edit.setText(f'${selected_asset[:-1]}')
                    else:
                        self.asset_checker.line_edit.setText('')
                else:
                    self.asset_checker.line_edit.setText('')
                    self.asset_checker.line_edit.setEnabled(selected_index > 0)
            self.asset_checker.validate_text()

        self.clayout = ChoicesLayout(_('Asset type'), [x[0] for x in self.asset_types], on_clicked=clayout_on_edit, checked_index=0)
        self.burn_address = self.asset_types[self.clayout.selected_index()][2]
        self.burn_amount = self.asset_types[self.clayout.selected_index()][3]

        grid.addLayout(self.clayout.layout(), 0, 0, 6, 1)

        self.parent_asset_selector_combo = QComboBox()
        self.parent_asset_selector_combo.setVisible(False)
        no_resize = self.parent_asset_selector_combo.sizePolicy()
        no_resize.setRetainSizeWhenHidden(True)
        self.parent_asset_selector_combo.setSizePolicy(no_resize)

        def parent_asset_selector_on_change():
            selected_parent_index = self.parent_asset_selector_combo.currentIndex()
            if selected_parent_index == 0:
                self.asset_checker.line_edit.setEnabled(False)
                self.asset_checker.line_edit.setText('')
                parent_is_valid = False
            else:
                parent_is_valid = self.parent_assets[selected_parent_index - 1][1]
            self.parent_is_ok = parent_is_valid
            self.asset_checker.line_edit.setEnabled(selected_parent_index > 0)
            selected_asset_type_index = self.clayout.selected_index()
            asset_type = self.asset_types[selected_asset_type_index][1]
            current_text = self.asset_checker.line_edit.text()
            if asset_type == AssetType.ROOT:
                user_text = ''
            elif asset_type == AssetType.SUB:
                split = current_text.split('/')
                if len(split) > 1:
                    user_text = split[-1]
                else:
                    user_text = ''
            elif asset_type == AssetType.UNIQUE:
                split = current_text.split('#')
                if len(split) > 1:
                    user_text = split[-1]
                else:
                    user_text = ''
            elif asset_type == AssetType.MSG_CHANNEL:
                split = current_text.split('~')
                if len(split) > 1:
                    user_text = split[-1]
                else:
                    user_text = ''
            elif asset_type == AssetType.QUALIFIER:
                user_text = current_text[1:]
            elif asset_type == AssetType.SUB_QUALIFIER:
                split = current_text.split('#')
                if len(split) > 1:
                    user_text = split[-1]
                else:
                    user_text = ''
            else:
                user_text = ''
            prefix = self.get_prefix(asset_type)
            self.asset_checker.line_edit.setText(prefix + user_text)
            self.asset_checker.validate_text()

        self.parent_asset_selector_combo.currentIndexChanged.connect(parent_asset_selector_on_change)

        grid.addWidget(self.parent_asset_selector_combo, 0, 2, 1, 9)

        # We don't want to query the server every click
        async def check_if_asset_exists():
            if not self.parent.network:
                self.asset_checker.error_button.setToolTip(_("You are offline."))
                self.asset_checker.error_button.show()
                return
            try:
                raw_metadata = await self.parent.network.get_asset_metadata(self.asset_checker.line_edit.text())
            except UntrustedServerReturnedError as e:
                self.asset_checker.error_button.setToolTip(_("Error getting asset from network") + ":\n" + e.get_message_for_gui())
                self.asset_checker.error_button.show()
                return
            except Exception as e:
                self.asset_checker.error_button.setToolTip(_("Error getting asset from network") + ":\n" + repr(e))
                self.asset_checker.error_button.show()
                return
            if raw_metadata:
                # Cannot create
                self.asset_checker.error_button.setToolTip(_("This asset already exists!"))
                self.asset_checker.error_button.show()
                pass
            else:
                self.asset_is_ok = True
                self._maybe_enable_pay_button()

        def asset_name_fast_fail(asset: str):
            selected_index = self.clayout.selected_index()
            if self.asset_types[selected_index][1] in (AssetType.ROOT, AssetType.SUB, AssetType.QUALIFIER, AssetType.SUB_QUALIFIER):
                asset = asset.upper()

            prefix = self.get_prefix(self.asset_types[selected_index][1])
            if asset[:len(prefix)] != prefix:
                asset = prefix + asset[len(prefix):]

            self.asset_checker.line_edit.setText(asset)

            self.amount_e.update()
            # Disable the button no matter what
            self.asset_is_ok = False
            self.send_button.setEnabled(False)
            error = get_error_for_asset_typed(asset, self.asset_types[self.clayout.selected_index()][1])
            return error

        self.asset_checker = ValidatedDelayedCallbackEditor(get_asyncio_loop, asset_name_fast_fail, 0.5, check_if_asset_exists)

        asset_label = QLabel(_('Name'))
        grid.addWidget(asset_label, 1, 1)
        grid.addWidget(self.asset_checker.line_edit, 1, 2, 1, 9)
        grid.addWidget(self.asset_checker.error_button, 1, 11)

        amount_label = QLabel(_('Amount'))
        self.amount_e = AssetAmountEdit(lambda: self.asset_checker.line_edit.text()[:4], 0, DEFAULT_ASSET_AMOUNT_MAX * COIN, parent=self, min_amount=COIN)
        self.amount_e.setText('1')
        grid.addWidget(amount_label, 2, 1)
        grid.addWidget(self.amount_e, 2, 2)

        divisions_message = _('Asset Divisions') + '\n\n' \
                            + _('Asset divisions are a number from 0 to 8 and denote how many digits past the decimal point can be used. Once an asset is issued, you cannot decrease this number.')
        divisions_label = HelpLabel(_('Divisions'), divisions_message)

        self.divisions_e = OnlyNumberAmountEdit(None, 0, 8, parent=self, callback=self._on_divisions_change)
        divisions_width = char_width_in_lineedit() * 3
        self.divisions_e._width = divisions_width
        self.divisions_e.setMaximumWidth(divisions_width)
        self.divisions_e.setAlignment(Qt.AlignCenter)
        self.divisions_e.setText('0')

        grid.addWidget(divisions_label, 2, 4)
        grid.addWidget(self.divisions_e, 2, 5)

        reissue_label = QLabel(_('Reissuable'))
        self.reissuable = QCheckBox(checked=True)

        grid.addWidget(reissue_label, 2, 7)
        grid.addWidget(self.reissuable, 2, 8)

        associated_data_message = _('Associated Data') + '\n\n' \
                            + _('Data that is associated with an asset. Typically an IPFS hash, but can be a TXID. Leave blank to associate no data.')
        associated_data_label = HelpLabel(_('Associated Data'), associated_data_message)

        def associated_data_fast_fail(input: str):
            self.associated_data_is_ok = False
            self.send_button.setEnabled(False)
            if len(input) == 0:
                self.associated_data_is_ok = True
                self._maybe_enable_pay_button()
                return None
            try:
                if len(input) % 2 == 1 and len(input) > 2 and len(input) < 64:
                    input = input[:-1]
                raw_bytes = bytes.fromhex(input)
                if len(raw_bytes) < 32:
                    return _('Too few bytes for a TXID')
                elif len(raw_bytes) > 32:
                    return _('Too many bytes for a TXID')
                else:
                    self.associated_data_is_ok = True
                    self._maybe_enable_pay_button()
                    return None
            except ValueError:
                try:
                    raw_bytes = base_decode(input, base=58)
                    if len(raw_bytes) < 34:
                        return _('Too few bytes for an IPFS hash')
                    elif len(raw_bytes) > 34:
                        return _('Too many bytes for an IPFS hash')
                    else:
                        self.associated_data_is_ok = True
                        self._maybe_enable_pay_button()
                        return None
                except BaseDecodeError:
                    return _('Failed to parse input')

        grid.addWidget(associated_data_label, 3, 1)
        self.associated_data_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, associated_data_fast_fail, 0, lambda: asyncio.sleep(0))
        grid.addWidget(self.associated_data_e.line_edit, 3, 2, 1, 9)
        grid.addWidget(self.associated_data_e.error_button, 3, 11)

        def address_fast_fail(input: str):
            self.address_is_ok = False
            self.send_button.setEnabled(False)
            if input and not is_address(input): 
                return _('Not a valid address')
            self.address_is_ok = True
            self._maybe_enable_pay_button()
            return None

        self.payto_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, address_fast_fail, 0, lambda: asyncio.sleep(0))

        pay_to_msg = (_("The recipient of the new asset.") + "\n\n"
               + _("If a Bitcoin address is entered, the asset (and any created ownership assets) "
                   "will be sent to this address. "
                   "Leave this empty to send to yourself."))
        payto_label = HelpLabel(_('Recieving Address'), pay_to_msg)
        grid.addWidget(payto_label, 4, 1)
        grid.addWidget(self.payto_e.line_edit, 4, 2, 1, 9)
        grid.addWidget(self.payto_e.error_button, 4, 11)

        self.send_button = EnterButton(_("Pay") + f" {self.burn_amount} RVN...", self.create_asset)
        self.send_button.setEnabled(False)
        self.send_button.setMinimumWidth(char_width_in_lineedit() * 16)

        grid.addWidget(self.send_button, 5, 8)

        vbox = QVBoxLayout(self)
        vbox.addLayout(grid)

    def _maybe_enable_pay_button(self):
        self.send_button.setEnabled(self.associated_data_is_ok and self.address_is_ok and self.asset_is_ok and self.parent_is_ok)

    def _on_divisions_change(self, amount):
        if amount is None:
            return
        assert isinstance(amount, int)
        self.amount_e.divisions = amount
        self.amount_e.is_int = amount == 0
        self.amount_e.min_amount = Decimal('1' if amount == 0 else f'0.{"".join("0" for i in range(amount - 1))}1') * COIN
        self.amount_e.numbify()
        self.amount_e.update()

    def create_asset(self):
        output = PartialTxOutput.from_address_and_value(self.burn_address, self.burn_amount * COIN)
        outputs = [output]
        goto_address = self.payto_e.line_edit.text()
        
        asset = self.asset_checker.line_edit.text()
        amount = self.amount_e.get_amount()
        assert isinstance(amount, int)
        divisions = self.divisions_e.get_amount()
        assert isinstance(divisions, int)
        reissuable = self.reissuable.isChecked()
        associated_data = None
        associated_data_raw = self.associated_data_e.line_edit.text()
        if associated_data_raw:
            try:
                associated_data = b'\x54\x20' + bytes.fromhex(associated_data_raw)
            except ValueError:
                associated_data = base_decode(associated_data_raw, base=58)

        if not goto_address:
            asset_change_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
        else:
            asset_change_address = goto_address

        output_amounts = {
            None: self.burn_amount * COIN,
            asset: amount,
            f'{asset}!': COIN,
        }

        selected_asset_type_index = self.clayout.selected_index()
        asset_type = self.asset_types[selected_asset_type_index][1]
        if asset_type not in (AssetType.ROOT, AssetType.QUALIFIER):
            parent_asset = self.get_owner_asset()
            output_amounts[parent_asset] = COIN
            # TODO: New address for this
            outputs.append(PartialTxOutput.from_address_and_value(asset_change_address, COIN, asset=parent_asset))

        def make_tx(fee_est, *, confirmed_only=False):
            if not goto_address:
                # Freeze a change address so it is seperate from the rvn change
                self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=True)

            owner_script = generate_owner_script(asset_change_address, asset)
            create_script = generate_create_script(asset_change_address, asset, amount, divisions, reissuable, associated_data)

            owner_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(owner_script), value=0)
            create_vout = PartialTxOutput(scriptpubkey=bytes.fromhex(create_script), value=0)

            def fee_mixin(fee_est):
                def new_fee_estimator(size):
                    # size is virtual bytes

                    # We shouldn't need to worry about vout size varint increasing
                    owner_size = len(owner_vout.serialize_to_network())
                    create_size = len(create_vout.serialize_to_network())
                    return fee_est(size + owner_size + create_size)
            
                return new_fee_estimator

            tx = self.parent.wallet.make_unsigned_transaction(
                coins=self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                outputs=outputs,
                fee=fee_est,
                rbf=False,
                fee_mixin=fee_mixin
            )

            tx.add_outputs([owner_vout, create_vout], do_sort=False)

            if not goto_address:
                self.parent.wallet.set_reserved_state_of_address(asset_change_address, reserved=False)
            
            return tx

        conf_dlg = ConfirmTxDialog(window=self.parent.window, make_tx=make_tx, output_value=output_amounts)
        if conf_dlg.not_enough_funds:
            # note: use confirmed_only=False here, regardless of config setting,
            #       as the user needs to get to ConfirmTxDialog to change the config setting
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.get_text_not_enough_funds_mentioning_frozen()
                self.parent.show_message(text)
                return
        tx = conf_dlg.run()
        if tx is None:
            # user cancelled
            return
        is_preview = conf_dlg.is_preview
        if is_preview:
            self.parent.window.show_transaction(tx)
            return
        def sign_done(success):
            if success:
                self.parent.window.broadcast_or_show(tx)
        self.parent.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=None)
        
    def get_text_not_enough_funds_mentioning_frozen(self) -> str:
        text = _("Not enough funds")
        frozen_str = self.get_frozen_balance_str()
        if frozen_str:
            text += " ({} {})".format(
                frozen_str, _("are frozen")
            )
        return text

    def get_frozen_balance_str(self) -> Optional[str]:
        frozen_bal = sum(self.wallet.get_frozen_balance())
        if not frozen_bal:
            return None
        return self.format_amount_and_units(frozen_bal)

    def update_parent_assets(self, types:Sequence[AssetType]):
        balance: Mapping[Optional[str], Tuple[int, int, int]] = self.parent.wallet.get_balance(asset_aware=True)
        # confirmed, unconfirmed, unmatured
        parent_assets = set()
        for asset, amount in balance.items():
            if asset is None: continue
            if asset[-1] != '!': continue
            if sum(amount) == 0: continue
            parent_asset_name = asset[:-1]
            if all(get_error_for_asset_typed(parent_asset_name, asset_type) for asset_type in types): continue
            parent_assets.add(asset)

        avaliable_parent_assets = sorted(list((asset, balance[asset][1] == 0 and balance[asset][2] == 0) for asset in parent_assets), key=lambda x: x[0])
        if avaliable_parent_assets == self.parent_assets:
            return
        if not avaliable_parent_assets:
            self.parent_asset_selector_combo.clear()
            self.parent_asset_selector_combo.addItems([_('You do not own any compatible assets')])
            self.parent_asset_selector_combo.setCurrentIndex(0)
            self.parent_asset_selector_combo.setEnabled(False)
        else:
            current_selected_asset = None
            current_selected_asset_index = self.parent_asset_selector_combo.currentIndex()
            if current_selected_asset_index > 0:
                current_selected_asset = self.parent_assets[current_selected_asset_index - 1][0]
            items = [_('Select an asset')]
            items.extend((x[0] if x[1] else _('{} (mempool)').format(x[0])) for x in avaliable_parent_assets)
            self.parent_asset_selector_combo.clear()
            self.parent_asset_selector_combo.addItems(items)
            self.parent_asset_selector_combo.model().item(0).setEnabled(False)
            for i, (asset, valid) in enumerate(avaliable_parent_assets):
                if not valid:
                    self.parent_asset_selector_combo.model().item(i+1).setEnabled(False)
                if asset == current_selected_asset:
                    self.parent_asset_selector_combo.setCurrentIndex(i+1)
            self.parent_asset_selector_combo.setEnabled(True)

        self.parent_assets = avaliable_parent_assets

    def get_owner_asset(self):
        current_selected_asset_index = self.parent_asset_selector_combo.currentIndex()
        if current_selected_asset_index > 0:
            return self.parent_assets[current_selected_asset_index - 1][0]
        return None

    def get_prefix(self, type_: AssetType):
        if type_ == AssetType.QUALIFIER:
            return '#'
        asset = self.get_owner_asset()
        if asset is None: return ''
        if type_ == AssetType.SUB:
            return f'{asset[:-1]}/'
        elif type_ == AssetType.UNIQUE:
            return f'{asset[:-1]}#'
        elif type_ == AssetType.MSG_CHANNEL:
            return f'{asset[:-1]}~'
        elif type_ == AssetType.SUB_QUALIFIER:
            return f'{asset}/#'
        return ''

class AssetTab(QWidget, MessageBoxMixin, Logger):
    
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.network = window.network

        self.view_asset_tab = ViewAssetPanel(self)

        if self.wallet.is_watching_only():
            self.create_asset_tab = QLabel(_('Watch only wallets cannot create assets'))
            self.create_asset_tab.setAlignment(Qt.AlignCenter)
        else:
            self.create_asset_tab = CreateAssetPanel(self)

        self.info_label = QLabel(_('Select a tab below to view, create, and manage your assets'))
        self.info_label.setAlignment(Qt.AlignCenter)

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.view_asset_tab, read_QIcon("eye1.png"), _('View'))
        tabs.addTab(self.create_asset_tab, read_QIcon("preferences.png"), _('Create'))
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self.info_label)
        vbox.addWidget(self.tabs)

    def update(self):
        self.view_asset_tab.update()
        # TODO: update create tab
        super().update()

    def refresh_all(self):
        self.view_asset_tab.asset_list.update()
        # TODO: refresh create tab