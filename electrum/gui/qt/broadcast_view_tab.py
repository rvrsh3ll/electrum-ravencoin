import enum
from typing import TYPE_CHECKING

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, pyqtSignal, QItemSelectionModel, QPoint
from PyQt5.QtWidgets import (QAbstractItemView, QWidget, QHBoxLayout, QVBoxLayout, QToolButton, QMenu,
                             QLineEdit)

from .my_treeview import MyTreeView, MyMenu
from .util import IPFSViewer, read_QIcon, EnterButton, MessageBoxMixin

from electrum.asset import get_error_for_asset_typed, AssetType
from electrum.bitcoin import base_decode
from electrum.i18n import _
from electrum.logging import Logger
from electrum.util import profiler, SearchableListGrouping

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class BroadcastAssetList(MyTreeView):

    class Columns(MyTreeView.BaseColumnsEnum):
        ASSET = enum.auto()

    headers = {
        Columns.ASSET: _('Asset')
    }

    filter_columns = [Columns.ASSET]

    ROLE_ASSET_STR = Qt.UserRole + 1001
    key_role = ROLE_ASSET_STR

    def __init__(self, parent: 'ViewBroadcastTab', main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_columns=[self.Columns.ASSET]
        )
        self.parent = parent
        self.wallet = main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.current_assets = []
        self.last_selected_asset = None

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                parent.update_asset_trigger.emit(None)
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.ASSET)
            self.last_selected_asset = asset = m.data(self.ROLE_ASSET_STR)
            parent.update_asset_trigger.emit(asset)

        self.selectionModel().selectionChanged.connect(selectionChange)
    

    @profiler(min_threshold=0.05)
    def update(self):
        assets = self.wallet.adb.get_broadcasts_to_watch()
        if assets == self.current_assets:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, asset in enumerate(assets):
            labels = [""] * len(self.Columns)
            labels[self.Columns.ASSET] = asset
            row_item = [QStandardItem(x) for x in labels]
            row_item[self.Columns.ASSET].setData(asset, self.ROLE_ASSET_STR)
            self.model().insertRow(idx, row_item)
            self.refresh_row(asset, idx)
            if asset == self.last_selected_asset:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_assets = assets
        self.filter()


    def refresh_row(self, key: str, row: int) -> None:
        assert row is not None
        row_item = [self.std_model.item(row, col) for col in self.Columns]
        row_item[self.Columns.ASSET].setToolTip(key)


    def create_menu(self, position: QPoint):
        selected = self.selected_in_column(self.Columns.ASSET)
        if not selected:
            return
        multi_select = len(selected) > 1
        assets = [self.item_from_index(item).text() for item in selected]
        menu = QMenu()
        
        def remove_and_refresh(assets):
            for asset in assets:
                self.main_window.wallet.adb.remove_broadcast_to_watch(asset)
            self.parent.update_asset_trigger.emit(None)
            self.parent.update_associated_data_trigger.emit(None, None)
            self.update()

        if not multi_select:
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            item = self.item_from_index(idx)
            if not item:
                return
            asset = assets[0]
            menu.addAction(_('Stop Watching Asset'), lambda: remove_and_refresh([asset]))
        else:
            menu.addAction(_('Stop Watching Assets'), lambda: remove_and_refresh(assets))

        menu.exec_(self.viewport().mapToGlobal(position))


class BroadcastList(MyTreeView):
    
    class Columns(MyTreeView.BaseColumnsEnum):
        HEIGHT = enum.auto()
        DATA = enum.auto()
        TIMESTAMP = enum.auto()

    headers = {
        Columns.HEIGHT: _('Height'),
        Columns.DATA: _('Associated Data'),
        Columns.TIMESTAMP: _('Timestamp')
    }

    filter_columns = [Columns.HEIGHT, Columns.DATA, Columns.TIMESTAMP]

    ROLE_ID_STR = Qt.UserRole + 1001
    ROLE_ASSOCIATED_DATA_STR = Qt.UserRole + 1002
    key_role = ROLE_ID_STR

    def __init__(self, parent: 'ViewBroadcastTab', main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_columns=[self.Columns.DATA]
        )
        self.wallet = main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.current_asset = None
        self.current_broadcasts = None
        self.last_selected_broadcast_id = None

        def selectionChange(new, old):
            rows = [x.row() for x in new.indexes()]
            if not rows:
                parent.update_associated_data_trigger.emit(None, None)
                return
            first_row = min(rows)
            m = self.model().index(first_row, self.Columns.HEIGHT)
            self.last_selected_broadcast_id = m.data(self.ROLE_ID_STR)
            m = self.model().index(first_row, self.Columns.DATA)
            associated_data = m.data(self.ROLE_ASSOCIATED_DATA_STR)
            parent.update_associated_data_trigger.emit(self.current_asset, associated_data)

        self.selectionModel().selectionChanged.connect(selectionChange)
    
    @profiler(min_threshold=0.05)
    def update(self):
        broadcasts = self.wallet.adb.get_broadcasts(self.current_asset) if self.current_asset else []
        if broadcasts == self.current_broadcasts:
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, (associated_data, timestamp, height, tx_hash, tx_pos) in enumerate(broadcasts):
            labels = [""] * len(self.Columns)
            labels[self.Columns.HEIGHT] = str(height)
            labels[self.Columns.DATA] = associated_data
            labels[self.Columns.TIMESTAMP] = str(timestamp)
            row_item = [QStandardItem(x) for x in labels]
            id = f'{tx_hash}:{tx_pos}'
            row_item[self.Columns.HEIGHT].setData(id, self.ROLE_ID_STR)
            row_item[self.Columns.DATA].setData(associated_data, self.ROLE_ASSOCIATED_DATA_STR)
            self.model().insertRow(idx, row_item)
            self.refresh_row(associated_data, idx)
            if id == self.last_selected_broadcast_id:
                self.selectionModel().select(self.model().createIndex(idx, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.current_broadcasts = broadcasts
        self.filter()

    def refresh_row(self, key: str, row: int) -> None:
        assert row is not None
        row_item = [self.std_model.item(row, col) for col in self.Columns]
        row_item[self.Columns.DATA].setToolTip(key)


class ViewBroadcastTab(QWidget, Logger, MessageBoxMixin):
    update_asset_trigger = pyqtSignal(str)
    update_associated_data_trigger = pyqtSignal(str, str)

    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self)
        Logger.__init__(self)

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        self.asset_list = BroadcastAssetList(self, window)
        vbox.addWidget(self.asset_list)
        hbox.addLayout(vbox)
        vbox = QVBoxLayout()
        self.broadcast_list = BroadcastList(self, window)
        vbox.addWidget(self.broadcast_list, stretch=1)
        self.ipfs_viewer = IPFSViewer(window)
        vbox.addWidget(self.ipfs_viewer, stretch=1)
        hbox.addLayout(vbox)

        menu = MyMenu(window.config)
        menu.addConfig(_('Download IPFS'), window.config.cv.DOWNLOAD_IPFS, callback=self.ipfs_viewer.update_visibility)
        menu.addConfig(_('Display Downloaded IPFS'), window.config.cv.SHOW_IPFS, callback=self.ipfs_viewer.update_visibility)
        menu.addConfig(_('Show Metadata Sources'), window.config.cv.SHOW_METADATA_SOURCE, callback=lambda: None)

        toolbar_button = QToolButton()
        toolbar_button.setIcon(read_QIcon("preferences.png"))
        toolbar_button.setMenu(menu)
        toolbar_button.setPopupMode(QToolButton.InstantPopup)
        toolbar_button.setFocusPolicy(Qt.NoFocus)
        toolbar = QHBoxLayout()
        self.add_asset = QLineEdit()
        self.add_asset.setFixedWidth(200)
        self.add_asset.setMaxLength(32)
        toolbar.addWidget(self.add_asset)
        
        def watch_asset():
            asset = self.add_asset.text()
            if get_error_for_asset_typed(asset, AssetType.OWNER) and get_error_for_asset_typed(asset, AssetType.MSG_CHANNEL):
                self.show_warning(_('Not a valid owner asset or message channel.'))
                return
            window.wallet.adb.add_broadcast_to_watch(asset)
            self.add_asset.clear()
            self.update()

        self.watch_button = EnterButton(_('Watch Asset'), watch_asset)
        toolbar.addWidget(self.watch_button)
        toolbar.addStretch()
        toolbar.addWidget(toolbar_button)

        vbox = QVBoxLayout(self)
        vbox.addLayout(toolbar)
        vbox.addLayout(hbox)

        self.update_asset_trigger.connect(lambda x: self.switch_asset(x))
        self.update_associated_data_trigger.connect(lambda x, y: self.switch_associcated_data(x, y))

        self.searchable_list = SearchableListGrouping(self.asset_list, self.broadcast_list)

    def update(self):
        self.asset_list.update()
        self.broadcast_list.update()
        self.ipfs_viewer.update_visibility()

    def switch_asset(self, asset: str):
        self.broadcast_list.current_asset = asset
        self.broadcast_list.update()

    def switch_associcated_data(self, asset: str, associated_data: str):
        if not asset or not associated_data:
            self.ipfs_viewer.clear()
            return
        self.ipfs_viewer.update(asset, base_decode(associated_data, base=58))
