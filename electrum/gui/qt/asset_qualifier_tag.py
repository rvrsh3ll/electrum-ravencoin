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

class QualifierList(MyTreeView):
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

    def __init__(self, parent: 'QualifierAssetPanel'):
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

class QualifierAssetPanel(QSplitter, Logger):
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        self.asset_list = QualifierList(self)
        self.metadata_viewer = QLabel('TEST')

        self.asset_list.setMinimumWidth(300)
        self.metadata_viewer.setMinimumWidth(400)

        self.setChildrenCollapsible(False)
        self.addWidget(self.asset_list)
        self.addWidget(self.metadata_viewer)

        self.setStretchFactor(0, 1)
        self.setStretchFactor(1, 0)

    def update(self):
        self.asset_list.update()
        self.metadata_viewer.update()
        super().update()
