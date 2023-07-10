import enum
import math
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Tuple
from functools import lru_cache

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem, QPixmap, QMovie
from PyQt5.QtCore import pyqtSignal, Qt, QItemSelectionModel, QSize
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QSplitter, QScrollArea,
                             QHBoxLayout, QWidget, QFrame, QAbstractItemView,
                             QCheckBox, QMenu)

from electrum import constants
from electrum.asset import AssetMetadata
from electrum.bitcoin import base_encode
from electrum.i18n import _
from electrum.util import format_satoshis_plain, profiler, ipfs_explorer_URL
from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.logging import Logger

from electrum.ipfs_db import IPFSDB

from .util import HelpLabel, ColorScheme, HelpButton, AutoResizingTextEdit, qt_event_listener, QtEventListener
from .util import QHSeperationLine, read_QIcon, MONOSPACE_FONT, EnterButton, webopen_safe
from .my_treeview import MyTreeView

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from aiohttp import ClientResponse
    from .asset_tab import AssetTab

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
        watching_assets = [asset for asset, balance in self.wallet.get_balance(asset_aware=True).items() if asset and sum(balance) > 0 and not self.wallet.is_asset_in_blacklist(asset)]
        new_assets = sorted([(asset, (metadata[0].sats_in_circulation, metadata[1]) if ((metadata := self.wallet.adb.get_asset_metadata(asset)) is not None) else None) for asset in watching_assets], key=lambda x: x[0])
        if self.current_assets == new_assets:
            return
        self.parent.logger.info('refreshing asset view')
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

    def create_menu(self, position):
        selected = self.selected_in_column(self.Columns.ASSET)
        if not selected:
            return
        assets = [self.item_from_index(item).text() for item in selected]
        
        def mark_as_junk():
            for asset in assets:
                self.wallet.add_asset_regex_to_blacklist_for_asset(asset)
            self.parent.update_asset_trigger.emit(None)
            self.main_window.update_tabs()

        menu = QMenu()
        menu.addAction(_('Mark asset{} as junk').format('s' if len(assets) > 1 else ''), mark_as_junk)
        menu.exec_(self.viewport().mapToGlobal(position))
        
class MetadataInfo(QWidget, QtEventListener):
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

        self.associated_data_text = AutoResizingTextEdit()
        self.associated_data_text.setReadOnly(True)
        self.associated_data_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.associated_data_text.setAlignment(Qt.AlignVCenter)
        self.associated_data_text.setVisible(False)

        self.view_associated_data_button = EnterButton('', self._view_associated_data)
        self.view_associated_data_button.setVisible(False)
        
        self.associated_data_view_image = QLabel()
        self.associated_data_view_image.setVisible(False)
        self.associated_data_view_image.setAlignment(Qt.AlignLeft)

        self.associated_data_view_text = AutoResizingTextEdit()
        self.associated_data_view_text.setReadOnly(True)
        self.associated_data_view_text.setAlignment(Qt.AlignVCenter)
        self.associated_data_view_text.setVisible(False)
        
        associated_data_view_seperator = QHSeperationLine()
        associated_data_info_layout = QVBoxLayout()
        associated_data_info_layout.addWidget(associated_data_view_seperator)
        associated_data_info_layout.addLayout(associated_data_type_layout)
        associated_data_info_layout.addWidget(self.associated_data_text)
        associated_data_info_layout.addWidget(self.view_associated_data_button)
        associated_data_info_layout.addWidget(self.associated_data_view_image)
        associated_data_info_layout.addWidget(self.associated_data_view_text)

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
        associated_data_view_layout.addLayout(predicted_mime_type_layout)
        associated_data_view_layout.addLayout(predicted_size_layout)

        self.verifier_string_label = QLabel(_('Verifier String:'))
        self.verifier_string_label.setVisible(False)
        self.verifier_string_text = AutoResizingTextEdit()
        self.verifier_string_text.setReadOnly(True)
        self.verifier_string_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.verifier_string_text.setAlignment(Qt.AlignVCenter)
        self.verifier_string_text.setVisible(False)

        verifier_freeze_layout = QHBoxLayout()
        self.global_freeze_label = QLabel(_('Globally Frozen: '))
        self.global_freeze_label.setVisible(False)
        self.global_freeze_cb = QCheckBox()
        self.global_freeze_cb.setEnabled(False)
        self.global_freeze_cb.setVisible(False)
        verifier_freeze_layout.addWidget(self.global_freeze_label)
        verifier_freeze_layout.addWidget(self.global_freeze_cb, 1, Qt.AlignLeft)

        self.verifier_string_seperator = QHSeperationLine()
        self.verifier_string_seperator.setVisible(False)
        restricted_verifier_layout = QVBoxLayout()
        restricted_verifier_layout.addWidget(self.verifier_string_seperator)
        restricted_verifier_layout.addWidget(self.verifier_string_label)
        restricted_verifier_layout.addWidget(self.verifier_string_text)
        restricted_verifier_layout.addLayout(verifier_freeze_layout)
        
        vbox.addLayout(header_layout)
        vbox.addLayout(asset_layout)
        vbox.addLayout(type_layout)
        vbox.addLayout(basic_info_layout)
        vbox.addLayout(associated_data_info_layout)
        vbox.addLayout(associated_data_view_layout)
        vbox.addLayout(restricted_verifier_layout)
        vbox.addWidget(QWidget(), 1)
        self.clear()

        self.current_asset = None
        self.register_callbacks()

    @qt_event_listener
    def on_event_ipfs_download(self, ipfs_hash):
        self._update_associated_data_info(ipfs_hash)

    def _update_associated_data_info(self, ipfs_hash: str):
        if self.associated_data_text.toPlainText() != ipfs_hash:
            return
        saved_mime_type, saved_bytes = IPFSDB.get_instance().get_text_for_ipfs_str(ipfs_hash)
        self.predicted_mime_type_text.setText(saved_mime_type or _('Unknown'))
        self.predicted_size_text.setText(saved_bytes or _('Unknown'))

        for x in [self.associated_data_view_image, self.associated_data_view_text]:
            x.setVisible(False)
            x.clear()

        resource_path, resource_type = IPFSDB.get_instance().get_resource_path_for_ipfs_str(ipfs_hash)
        if resource_path and self.window.config.SHOW_IPFS:
            resource_data = self._get_viewable_from_resource_path(resource_path, resource_type)

            if resource_type == 'image/gif':
                pixmap, movie = resource_data
                scaled = pixmap.scaledToWidth(self.width() - 100, Qt.SmoothTransformation)
                movie.setScaledSize(QSize(scaled.width(), scaled.height()))
                self.associated_data_view_image.setMovie(movie)
                movie.start()
                self.associated_data_view_image.setVisible(True)
            elif resource_type.startswith('image/'):
                pixmap: QPixmap = resource_data
                scaled = pixmap.scaledToWidth(self.width() - 100, Qt.SmoothTransformation)
                self.associated_data_view_image.setPixmap(scaled)
                self.associated_data_view_image.setVisible(True)
            elif resource_type in ('text/plain', 'application/json'):
                self.associated_data_view_text.setText(resource_data)
                self.associated_data_view_text.setVisible(True)
            
            for x in [self.associated_data_text, self.view_associated_data_button, 
                        self.predicted_mime_type_label, self.predicted_size_label, 
                        self.predicted_mime_type_text, self.predicted_size_text]:
                x.setVisible(False)

    @lru_cache(50)
    def _get_viewable_from_resource_path(self, resource_path: str, resource_type: str):
        if resource_type == 'image/gif':
            return QPixmap(resource_path), QMovie(resource_path)
        elif resource_type.startswith('image/'):
            return QPixmap(resource_path)
        elif resource_type in ('text/plain', 'application/json'):
            with open(resource_path, 'r') as f:
                return f.read()

    def _view_associated_data(self):
        associated_data = self.associated_data_text.toPlainText()
        if len(associated_data) == 64:
            try:
                _b = bytes.fromhex(associated_data)
                self.window.do_process_from_txid(txid=associated_data)
                return
            except Exception:
                pass
        ipfs_url = ipfs_explorer_URL(self.window.config, 'ipfs', associated_data)
        webopen_safe(ipfs_url, self.window.config, self.window)

    def update(self, asset: str, type_text: Optional[str], metadata: AssetMetadata, 
               verifier_text, verifier_string_data,
               freeze_text, freeze_data):
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

        for x in [self.associated_data_view_image, self.associated_data_view_text]:
            x.setVisible(False)
            x.clear()

        if metadata.associated_data is None:
            self.associated_data_type_text.setText('None')
            for x in [self.associated_data_text, self.view_associated_data_button, 
                      self.predicted_mime_type_label, self.predicted_size_label, 
                      self.predicted_mime_type_text, self.predicted_size_text,
                      self.associated_data_view_image, self.associated_data_view_text]:
                x.setVisible(False)
            for x in [self.associated_data_view_image, self.associated_data_view_text]:
                x.clear()
            self.associated_data_text.clear()
        else:
            self.associated_data_text.setVisible(True)
            self.view_associated_data_button.setVisible(True)
            if metadata.associated_data[:2] == b'\x54\x20':
                self.view_associated_data_button.setText(_('Search Blockchain Transactions'))
                self.associated_data_type_text.setText('TXID')
                self.associated_data_text.setText(metadata.associated_data[2:].hex())
                for x in [self.predicted_mime_type_label, self.predicted_size_label, 
                          self.predicted_mime_type_text, self.predicted_size_text,
                          self.associated_data_view_image, self.associated_data_view_text]:
                    x.setVisible(False)
                for x in [self.associated_data_view_image, self.associated_data_view_text]:
                    x.clear()
            else:
                ipfs_str = base_encode(metadata.associated_data, base=58)
                self.associated_data_type_text.setText('IPFS')
                self.associated_data_text.setText(ipfs_str)
                self.view_associated_data_button.setText(_('View in Browser'))

                resource_path, resource_type = IPFSDB.get_instance().get_resource_path_for_ipfs_str(ipfs_str)
                if resource_path and self.window.config.SHOW_IPFS:
                    for x in [self.associated_data_text, self.view_associated_data_button, 
                              self.predicted_mime_type_label, self.predicted_size_label, 
                              self.predicted_mime_type_text, self.predicted_size_text]:
                        x.setVisible(False)

                    resource_data = self._get_viewable_from_resource_path(resource_path, resource_type)
                    if resource_type == 'image/gif':
                        pixmap, movie = resource_data
                        scaled = pixmap.scaledToWidth(self.width() - 100, Qt.SmoothTransformation)
                        movie.setScaledSize(QSize(scaled.width(), scaled.height()))
                        self.associated_data_view_image.setMovie(movie)
                        movie.start()
                        self.associated_data_view_image.setVisible(True)
                    elif resource_type.startswith('image/'):
                        pixmap: QPixmap = resource_data
                        scaled = pixmap.scaledToWidth(self.width() - 100, Qt.SmoothTransformation)
                        self.associated_data_view_image.setPixmap(scaled)
                        self.associated_data_view_image.setVisible(True)
                    elif resource_type in ('text/plain', 'application/json'):
                        self.associated_data_view_text.setText(resource_data)
                        self.associated_data_view_text.setVisible(True)
                else:
                    if self.window.config.DOWNLOAD_IPFS:
                        for x in [self.predicted_mime_type_label, self.predicted_size_label, 
                                  self.predicted_mime_type_text, self.predicted_size_text]:
                            x.setVisible(True)
                        for x in [self.associated_data_view_image, self.associated_data_view_text]:
                            x.setVisible(False)
                        for x in [self.associated_data_view_image, self.associated_data_view_text]:
                            x.clear()

                        saved_mime_type, saved_bytes = IPFSDB.get_instance().get_text_for_ipfs_str(ipfs_str)
                        self.predicted_mime_type_text.setText(saved_mime_type or _('Unknown'))
                        self.predicted_size_text.setText(saved_bytes or _('Unknown'))

                        async def download_all_ipfs_data():
                            # Ensure data tries to download even if we have the info
                            await IPFSDB.get_instance().maybe_get_info_for_ipfs_hash(self.window.network, ipfs_str, asset)
                            await IPFSDB.get_instance().maybe_download_data_for_ipfs_hash(self.window.network, ipfs_str)

                        self.window.run_coroutine_from_thread(download_all_ipfs_data(), ipfs_str)

        if verifier_string_data:
            for x in [self.verifier_string_label, self.verifier_string_text, self.verifier_string_seperator]:
                x.setVisible(True)
            label = _('Verifier String')
            if verifier_text:
                label += ' ' + verifier_text
            label += ':'
            self.verifier_string_label.setText(label)
            self.verifier_string_text.setText(verifier_string_data['string'])
        else:
            for x in [self.verifier_string_label, self.verifier_string_text, self.verifier_string_seperator]:
                x.setVisible(False)

        for x in [self.global_freeze_label, self.global_freeze_cb, self.verifier_string_seperator]:
            x.setVisible(bool(freeze_data))

        if freeze_data:
            label = _('Globally Frozen')
            if freeze_text:
                label += ' ' + freeze_text
            label += ':'
            self.global_freeze_label.setText(label)
            self.global_freeze_cb.setChecked(freeze_data['frozen'])

    def clear(self):
        self.header.setText('<h3>{}</h3>'.format(_('Asset Metadata')))
        for x in [self.asset_text, self.type_text, self.divisions_text, self.reissuable_text, self.associated_data_type_text]:
            x.setText(_('N/A'))

        self.associated_data_text.setText('')

        for x in [self.associated_data_text, self.verifier_string_label, 
                  self.verifier_string_seperator, self.verifier_string_text,
                  self.associated_data_view_image, self.associated_data_view_text]:
            x.setVisible(False)
        for x in [self.associated_data_view_image, self.associated_data_view_text]:
            x.clear()

        for x in [self.predicted_mime_type_text, self.predicted_size_text]:
            x.setText(_('N/A'))

        self.update_no_change()

    def update_no_change(self):
        associated_data_text = self.associated_data_text.toPlainText()
        for x in [self.associated_data_text, self.view_associated_data_button]:
            x.setVisible(bool(associated_data_text) and not self.window.config.SHOW_IPFS)
        if associated_data_text and associated_data_text.startswith('Qm'):
            for x in [self.predicted_mime_type_label, self.predicted_mime_type_text,
                      self.predicted_size_label, self.predicted_size_text]:
                x.setVisible(self.window.config.DOWNLOAD_IPFS)
            self._update_associated_data_info(associated_data_text)

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
        
        verifier_string_data = None
        verifier_string_text = None
        freeze_data = None
        freeze_text = None
        if asset[0] == '$':
            verifier_string_data_tup = self.parent.parent.wallet.adb.get_restricted_verifier_string(asset)
            if verifier_string_data_tup:
                verifier_string_data, verifier_string_type_id = verifier_string_data_tup
                if verifier_string_type_id == METADATA_UNCONFIRMED:
                    verifier_string_text = _('UNCONFIRMED')
                elif verifier_string_type_id == METADATA_UNVERIFIED:
                    verifier_string_text = _('NOT VERIFIED!')

            freeze_data_tup = self.parent.parent.wallet.adb.get_restricted_freeze(asset)
            if freeze_data_tup:
                freeze_data, freeze_type_id = freeze_data_tup
                if freeze_type_id == METADATA_UNCONFIRMED:
                    freeze_text = _('UNCONFIRMED')
                elif freeze_type_id == METADATA_UNVERIFIED:
                    freeze_text = _('NOT VERIFIED!')

        self.metadata_info.update(asset, type_text, metadata, 
                                  verifier_string_text, verifier_string_data, 
                                  freeze_text, freeze_data)

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
