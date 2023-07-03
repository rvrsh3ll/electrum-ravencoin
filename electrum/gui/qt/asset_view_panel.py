import enum
import math
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import pyqtSignal, Qt, QItemSelectionModel
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QSplitter, QScrollArea,
                             QHBoxLayout, QWidget, QFrame, QAbstractItemView,
                             QTextEdit)

from electrum.asset import AssetMetadata
from electrum.bitcoin import base_encode
from electrum.i18n import _
from electrum.util import format_satoshis_plain, profiler, ipfs_explorer_URL
from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.logging import Logger

from electrum.ipfs_db import IPFSDB

from .util import HelpLabel, ColorScheme, HelpButton
from .util import QHSeperationLine, read_QIcon, MONOSPACE_FONT, font_height
from .my_treeview import MyTreeView

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from aiohttp import ClientResponse
    from .asset_tab import AssetTab

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
                self.parent.update_asset_trigger.emit(None)
                return
            first_row = min(rows)
            self.last_selected_asset = asset = self.model().index(first_row, self.Columns.ASSET).data(self.ROLE_ASSET_STR)
            self.parent.update_asset_trigger.emit(asset)

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        watching_assets = [asset for asset, balance in self.wallet.get_balance(asset_aware=True).items() if asset and sum(balance) > 0]
        new_assets = [(asset, (metadata[0].sats_in_circulation, metadata[1]) if ((metadata := self.wallet.adb.get_asset_metadata(asset)) is not None) else None) for asset in watching_assets]
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
        self.associated_data_text.setVisible(False)

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
            x.setVisible(False)

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
    def __init__(self, parent: 'ViewAssetPanel'):
        QFrame.__init__(self)
        self.parent = parent
        self.metadata_info = MetadataInfo(parent.parent.window)

        scroll = QScrollArea()
        scroll.setWidget(self.metadata_info)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

    def update_info(self, asset: str):
        if asset is None:
            self.metadata_info.clear()
            return
        metadata_tup = self.parent.parent.wallet.adb.get_asset_metadata(asset)
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
    update_asset_trigger = pyqtSignal(str)

    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.asset_list = AssetList(self)
        self.metadata_viewer = MetadataViewer(self)

        self.asset_list.setMinimumWidth(300)
        self.metadata_viewer.setMinimumWidth(400)

        self.setChildrenCollapsible(False)
        self.addWidget(self.asset_list)
        self.addWidget(self.metadata_viewer)

        self.setStretchFactor(0, 1)
        self.setStretchFactor(1, 0)

        self.update_asset_trigger.connect(lambda asset: self.metadata_viewer.update_info(asset))

    def update(self):
        self.asset_list.update()
        self.metadata_viewer.update()
        super().update()
