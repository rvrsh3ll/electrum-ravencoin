from abc import abstractmethod
import asyncio
import enum
from typing import TYPE_CHECKING, List

from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QScrollArea, QLineEdit, QAbstractItemView, QMenu

from electrum.bitcoin import base_decode
from electrum.i18n import _
from electrum.network import UntrustedServerReturnedError
from electrum.util import profiler, ipfs_explorer_URL 
from electrum.transaction import TxOutpoint

from .my_treeview import MyTreeView
from .util import Buttons, CloseButton, read_QIcon, MONOSPACE_FONT, BlockingWaitingDialog, webopen_safe, WindowModalDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class HeightKey:
    # Makes negative numbers greater than all positive ones so that mempools come after them
    def __init__(self, height):
        self.height = height

    def __lt__(self, other):
        if isinstance(other, HeightKey):
            if self.height < 0:
                if other.height < 0:
                    return self.height < other.height
                else:
                    return False
            else:
                if other.height < 0:
                    return True
                else:
                    return self.height < other.height
        return self.height < other


class AbstractAssetDialog(WindowModalDialog):
    def __init__(self, window: 'ElectrumWindow', asset: str, *, parent=None):
        WindowModalDialog.__init__(self, parent or window, _('Asset'))
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


class _MetadataHistoryList(MyTreeView):
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
        for idx, history_item in enumerate(sorted(history, key=lambda x: (HeightKey(x['height']), x['tx_hash']), reverse=True)):
            labels = [""] * len(self.Columns)

            ipfs_str = _('Unchanged') if idx < (len(history) - 1) else _('None')
            if history_item['has_ipfs']:
                if history_item['ipfs'][:2] == 'Qm':
                    if self.config.SHOW_IPFS_AS_BASE32_CIDV1:
                        from electrum.ipfs_db import cidv0_to_base32_cidv1
                        ipfs_str = cidv0_to_base32_cidv1(history_item['ipfs'])
                    else:
                        ipfs_str = history_item['ipfs']
                else:
                    raw = base_decode(history_item['ipfs'], base=58)
                    assert raw[:2] == b'\x54\x20'
                    ipfs_str = raw[2:].hex()

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

    def create_menu(self, position):
        selected = self.selected_in_column(self.Columns.HEIGHT)
        if not selected:
            return
        if len(selected) > 1: return

        menu = QMenu()
        data = self.item_from_index(selected[0]).data(self.ROLE_DATA_DICT)
        menu.addAction(_('View Transaction'), lambda: self.main_window.do_process_from_txid(txid=data['tx_hash']))

        if data['has_ipfs']:
            data_str = self.item_from_index(selected[0]).data(self.ROLE_IPFS_STR)
            if data['ipfs'][:2] == 'Qm':
                def open_ipfs():
                    ipfs_url = ipfs_explorer_URL(self.main_window.config, 'ipfs', data_str)
                    webopen_safe(ipfs_url, self.main_window.config, self.main_window)
                menu.addAction(_('View IPFS'), open_ipfs)
            else:
                menu.addAction(_('Search Associated Transaction'), lambda: self.main_window.do_process_from_txid(txid=data_str))

        menu.exec_(self.viewport().mapToGlobal(position))


class LooseAssetMetadata:
    def __init__(self, sats_in_circulation, divisions, reissuable, associated_data):
        self.sats_in_circulation = sats_in_circulation
        self.divisions = divisions
        self.reissuable = reissuable
        self.associated_data = None

        if not associated_data:
            return
        if isinstance(associated_data, str) and len(associated_data) == 68:
            associated_data = bytes.fromhex(associated_data)
        if isinstance(associated_data, bytes):
            if len(associated_data) != 34:
                raise ValueError(f'{associated_data=} is not 34 bytes')
            self.associated_data = associated_data
        else:
            associated_data = base_decode(associated_data, base=58)
            if len(associated_data) != 34:
                raise ValueError(f'{associated_data=} decoded is not 34 bytes')
            self.associated_data = associated_data
        

class AssetMetadataHistory(AbstractAssetDialog):
    def _internal_widget(self):
        self.setWindowTitle(_('Metadata History For {}').format(self.asset))
        if not self.window.network:
            self.window.show_message(_("You are offline."))
            return None
        try:
            d: List = self.network.run_from_another_thread(
                self.network.get_metadata_history(self.asset)
            )

            if not d:
                self.window.show_message(_("This asset does not exist."))
                return None

            if self.window.config.VERIFY_TRANSITORY_ASSET_DATA:
                async def verify_all_txids():
                    await self.wallet.adb.verifier.wait_and_verify_transitory_transactions([(item['tx_hash'], item['height']) for item in d])
                    d.sort(key=lambda x: HeightKey(x['height']))
                    await asyncio.gather(*[
                        self.wallet.adb.verifier._internal_verify_unverified_asset_metadata(
                                self.asset, 
                                LooseAssetMetadata(
                                    sats_in_circulation=item['sats'],
                                    divisions=item['divisions'],
                                    reissuable=True,
                                    associated_data=item['ipfs'] if item['has_ipfs'] else None
                                ),
                                (TxOutpoint(bytes.fromhex(item['tx_hash']), item['tx_pos']), item['height']),
                                None,
                                None,
                                validate_against_verified=False
                            ) for item in d[:-1]])
                    
                    try:
                        item = d[-1]
                        faux_data = LooseAssetMetadata(
                            sats_in_circulation=item['sats'],
                            divisions=item['divisions'],
                            reissuable=True,
                            associated_data=item['ipfs'] if item['has_ipfs'] else None
                        )                
                        await self.wallet.adb.verifier._internal_verify_unverified_asset_metadata(
                            self.asset, 
                            faux_data,
                            (TxOutpoint(bytes.fromhex(item['tx_hash']), item['tx_pos']), item['height']),
                            None,
                            None,
                            validate_against_verified=False
                        ) 
                    except Exception:
                        faux_data.reissuable = False
                        self.window.logger.info(f'Got error... assuming reason was asset is now non-reissuable... retrying with relevant info...')
                        await self.wallet.adb.verifier._internal_verify_unverified_asset_metadata(
                            self.asset, 
                            faux_data,
                            (TxOutpoint(bytes.fromhex(item['tx_hash']), item['tx_pos']), item['height']),
                            None,
                            None,
                            validate_against_verified=False
                        )

                BlockingWaitingDialog(
                    self.window, 
                    _("Validating Transactions..."), 
                    lambda: self.network.run_from_another_thread(
                            verify_all_txids()))

            widget = _MetadataHistoryList(self.window)
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


class _VerifierHistoryList(MyTreeView):
    class Columns(MyTreeView.BaseColumnsEnum):
        HEIGHT = enum.auto()
        VERIFIER = enum.auto()

    headers = {
        Columns.HEIGHT: _('Height'),
        Columns.VERIFIER: _('Verifier String'),
    }

    filter_columns = [Columns.HEIGHT]

    ROLE_KEY_STR = Qt.UserRole + 1000
    ROLE_DATA_DICT = Qt.UserRole + 1001
    key_role = ROLE_KEY_STR

    def __init__(self, window: 'ElectrumWindow'):
        super().__init__(
            main_window=window,
            stretch_columns=[self.Columns.VERIFIER]
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
        for idx, history_item in enumerate(sorted(history, key=lambda x: (HeightKey(x['height']), x['tx_hash']), reverse=True)):
            labels = [""] * len(self.Columns)

            labels[self.Columns.HEIGHT] = str(history_item['height']) if history_item['height'] >= 0 else _('N/A')
            labels[self.Columns.VERIFIER] = history_item['string']
            row_item = [QStandardItem(x) for x in labels]
            icon = read_QIcon('unconfirmed.png') if history_item['height'] < 0 else read_QIcon('confirmed.png')
            row_item[self.Columns.HEIGHT] = QStandardItem(icon, labels[self.Columns.HEIGHT])
            self.set_editability(row_item)
            row_item[self.Columns.HEIGHT].setData(history_item['tx_hash'], self.ROLE_KEY_STR)
            row_item[self.Columns.HEIGHT].setData(history_item, self.ROLE_DATA_DICT)
            row_item[self.Columns.VERIFIER].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, row_item)
            self.refresh_row(history_item['tx_hash'], history_item, idx)
        self.filter()

    def refresh_row(self, key: str, data, row: int) -> None:
        assert row is not None
        asset_item = [self.std_model.item(row, col) for col in self.Columns]
        asset_item[self.Columns.VERIFIER].setToolTip(asset_item[self.Columns.HEIGHT].data(self.ROLE_DATA_DICT)['string'])
        
    def on_double_click(self, idx):
        data = self.get_role_data_for_current_item(col=self.Columns.HEIGHT, role=self.ROLE_DATA_DICT)
        tx_hash = data['tx_hash']
        self.main_window.do_process_from_txid(txid=tx_hash)


class AssetVerifierHistory(AbstractAssetDialog):
    def _internal_widget(self):
        self.setWindowTitle(_('Verifier History For {}').format(self.asset))
        if not self.window.network:
            self.window.show_message(_("You are offline."))
            return None
        try:
            d = self.network.run_from_another_thread(
                self.network.get_verifier_history(self.asset)
            )

            if not d:
                self.window.show_message(_("This asset does not exist."))
                return None

            if self.window.config.VERIFY_TRANSITORY_ASSET_DATA:
                async def verify_all_txids():
                    await self.wallet.adb.verifier.wait_and_verify_transitory_transactions([(item['tx_hash'], item['height']) for item in d])
                    await asyncio.gather(*[
                        self.wallet.adb.verifier._internal_verify_unverified_restricted_verifier(
                                self.asset, 
                                item
                            ) for item in d])

                BlockingWaitingDialog(
                    self.window, 
                    _("Validating Transactions..."), 
                    lambda: self.network.run_from_another_thread(
                            verify_all_txids()))

            widget = _VerifierHistoryList(self.window)
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
