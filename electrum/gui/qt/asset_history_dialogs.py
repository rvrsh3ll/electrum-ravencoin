from abc import abstractmethod
import enum
from typing import TYPE_CHECKING

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QScrollArea, QLineEdit, QDialog, QWidget, QAbstractItemView

from electrum.i18n import _
from electrum.network import UntrustedServerReturnedError
from electrum.util import profiler

from .my_treeview import MyTreeView
from .util import Buttons, CloseButton, MessageBoxMixin, read_QIcon, MONOSPACE_FONT, BlockingWaitingDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class AbstractAssetDialog(QDialog, MessageBoxMixin):
    def __init__(self, window: 'ElectrumWindow', asset: str):
        QDialog.__init__(self, parent=window)
        self.asset = asset
        self.window = window
        self.wallet = window.wallet
        self.network = window.network
        self.valid = False

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        self.search_box = QLineEdit()
        self.search_box.textChanged.connect(self.do_search)
        self.search_box.hide()

        scroll = QScrollArea()
        if (widget := self._internal_widget()) is None:
            return
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        vbox.addWidget(self.search_box)
        vbox.addWidget(scroll)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.valid = True

    @abstractmethod
    def _internal_widget(self):
        pass

    @abstractmethod
    def do_search(self, text):
        pass

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.ControlModifier and event.key() == Qt.Key_F:
            self.search_box.setHidden(not self.search_box.isHidden())
            if not self.search_box.isHidden():
                self.search_box.setFocus(1)
            else:
                self.do_search('')
        super().keyPressEvent(event)


class _AssociatedRestrictedAssetList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        HEIGHT = enum.auto()
        SATS_ADDED = enum.auto()
        DIVISIONS = enum.auto()
        ASSOCIATED_DATA = enum.auto()

    headers = {
        Columns.HEIGHT: _('Height'),
        Columns.SATS_ADDED: _('Amount Added'),
        Columns.DIVISIONS: _('Divisions'),
        Columns.ASSOCIATED_DATA: _('Associated Data'),
    }

    filter_columns = [Columns.HEIGHT]

    ROLE_KEY_STR = Qt.UserRole + 1000
    ROLE_DATA_DICT = Qt.UserRole + 1001
    ROLE_IPFS_STR = Qt.UserRole + 1002
    key_role = ROLE_KEY_STR

    def __init__(self, window: 'ElectrumWindow'):
        super().__init__(
            main_window=window,
            stretch_columns=[self.Columns.ASSOCIATED_DATA]
        )
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    @profiler(min_threshold=0.05)
    def update(self, history):
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, history_item in enumerate(sorted(history, key=lambda x: (x['height'], x['tx_hash']), reverse=True)):
            labels = [""] * len(self.Columns)

            ipfs_str = _('Unchanged')
            if history_item['has_ipfs']:
                if self.config.SHOW_IPFS_AS_BASE32_CIDV1:
                    from electrum.ipfs_db import cidv0_to_base32_cidv1
                    ipfs_str = cidv0_to_base32_cidv1(history_item['ipfs'])
                else:
                    ipfs_str = history_item['ipfs']

            labels[self.Columns.HEIGHT] = str(history_item['height']) if history_item['height'] >= 0 else _('N/A')
            labels[self.Columns.SATS_ADDED] = self.config.format_amount(history_item['sats'], add_thousands_sep=True)
            labels[self.Columns.DIVISIONS] = str(history_item['divisions']) if history_item['divisions'] != 0xff else _('Unchanged')
            labels[self.Columns.ASSOCIATED_DATA] = ipfs_str
            row_item = [QStandardItem(x) for x in labels]
            icon = read_QIcon('unconfirmed.png') if history_item['height'] < 0 else read_QIcon('confirmed.png')
            row_item[self.Columns.HEIGHT] = QStandardItem(icon, labels[self.Columns.HEIGHT])
            self.set_editability(row_item)
            row_item[self.Columns.HEIGHT].setData(ipfs_str, self.ROLE_IPFS_STR)
            row_item[self.Columns.HEIGHT].setData(history_item['tx_hash'], self.ROLE_KEY_STR)
            row_item[self.Columns.HEIGHT].setData(history_item, self.ROLE_DATA_DICT)
            row_item[self.Columns.ASSOCIATED_DATA].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, row_item)
            self.refresh_row(history_item['tx_hash'], history_item, idx)
        self.filter()

    def refresh_row(self, key: str, data, row: int) -> None:
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        asset_item[self.Columns.ASSOCIATED_DATA].setToolTip(asset_item[self.Columns.HEIGHT].data(self.ROLE_IPFS_STR))
        
    def on_double_click(self, idx):
        data = self.get_role_data_for_current_item(col=self.Columns.HEIGHT, role=self.ROLE_DATA_DICT)
        tx_hash = data['tx_hash']
        self.main_window.do_process_from_txid(txid=tx_hash)


class AssetMetadataHistory(AbstractAssetDialog):
    def _internal_widget(self):
        self.setWindowTitle(_('Metadata History For {}').format(self.asset))
        if not self.window.network:
            self.window.show_message(_("You are offline."))
            return None
        try:
            d = self.network.run_from_another_thread(
                self.network.get_metadata_history(self.asset)
            )

            async def verify_all_txids():
                if not self.window.config.VERIFY_TRANSITORY_ASSET_DATA:
                    return
                await self.wallet.adb.verifier.wait_until_transactions_can_be_verified([(item['tx_hash'], item['height']) for item in d])

            BlockingWaitingDialog(self.window, _("Validating Transactions..."), 
                                    lambda: self.network.run_from_another_thread(
                                    verify_all_txids()))

            widget = _AssociatedRestrictedAssetList(self.window)
            widget.update(d)
            return widget
        except UntrustedServerReturnedError as e:
            self.window.logger.info(f"Error getting info from network: {repr(e)}")
            self.window.show_message(
                _("Error getting info from network") + ":\n" + e.get_message_for_gui()
            )
        except Exception as e:
            self.window.show_message(
                _("Error getting info from network") + ":\n" + repr(e)
            )            
        return None

    def do_search(self, text):
        pass
