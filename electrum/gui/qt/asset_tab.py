import asyncio
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Sequence, List, Callable, Any
from urllib.parse import urlparse

from PyQt5.QtGui import QFontMetrics, QFont
from PyQt5.QtCore import pyqtSignal, QPoint, Qt
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QGridLayout, QSizePolicy, QLineEdit, QCheckBox,
                             QHBoxLayout, QCompleter, QWidget, QToolTip, QPushButton, QTabWidget)

from electrum import util, paymentrequest
from electrum import lnutil
from electrum.asset import get_error_for_asset_typed, AssetType, DEFAULT_ASSET_AMOUNT_MAX
from electrum.bitcoin import base_decode, BaseDecodeError
from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.util import (get_asyncio_loop, FailedToParsePaymentIdentifier,
                           InvalidBitcoinURI, maybe_extract_lightning_payment_identifier, NotEnoughFunds,
                           NoDynamicFeeEstimates, InvoiceError, parse_max_spend)
from electrum.invoices import PR_PAID, Invoice, PR_BROADCASTING, PR_BROADCAST
from electrum.transaction import Transaction, PartialTxInput, PartialTransaction, PartialTxOutput
from electrum.network import TxBroadcastError, BestEffortRequestFailed, UntrustedServerReturnedError
from electrum.logging import Logger
from electrum.lnaddr import lndecode, LnInvoiceException
from electrum.lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, LNURL6Data

from .amountedit import AmountEdit, BTCAmountEdit, SizedFreezableLineEdit
from .util import WaitingDialog, HelpLabel, MessageBoxMixin, char_width_in_lineedit, GenericInputHandler
from .util import get_iconname_camera, get_iconname_qrcode, read_QIcon, MONOSPACE_FONT, ChoicesLayout, ValidatedDelayedCallbackEditor
from .confirm_tx_dialog import ConfirmTxDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class AssetAmountEdit(AmountEdit):
    def __init__(self, asset_name: Callable[[], str], divisions: int, max_amount: int, *, parent=None, min_amount=0, callback=None):
        AmountEdit.__init__(self, asset_name, True, parent, max_amount=max_amount, min_amount=min_amount, callback=callback)
        self.divisions = divisions

    def decimal_point(self):
        return self.divisions

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.setText('')
        return super().numbify()

class CreateAssetPanel(QWidget, Logger):
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

        asset_types = (
            ('Main', AssetType.ROOT),
            ('Sub', AssetType.SUB),
            ('Unique', AssetType.UNIQUE),
            ('Message', AssetType.MSG_CHANNEL),
            ('Qualifier', AssetType.QUALIFIER),
            ('Sub Qualifier', AssetType.SUB_QUALIFIER),
            ('Restricted', AssetType.RESTRICTED),             
        )

        def clayout_on_edit(clayout: ChoicesLayout):
            self.asset_checker.validate_text()

        clayout = ChoicesLayout(_('Asset type'), [x[0] for x in asset_types], on_clicked=clayout_on_edit, checked_index=0)

        grid.addLayout(clayout.layout(), 0, 0, 6, 1)

        grid.addWidget(QLabel('PLACEHOLDER'), 0, 1)

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

        def asset_name_fast_fail(asset: str):
            self.amount_e.update()
            # Disable the button no matter what
            self.asset_is_ok = False
            error = get_error_for_asset_typed(asset, asset_types[clayout.selected_index()][1])
            return error

        self.asset_checker = ValidatedDelayedCallbackEditor(get_asyncio_loop, asset_name_fast_fail, 0.75, check_if_asset_exists)

        asset_label = QLabel(_('Name'))
        grid.addWidget(asset_label, 1, 1)
        grid.addWidget(self.asset_checker.line_edit, 1, 2, 1, 9)
        grid.addWidget(self.asset_checker.error_button, 1, 11)

        amount_label = QLabel(_('Amount'))
        self.amount_e = AssetAmountEdit(lambda: self.asset_checker.line_edit.text()[:4], 0, DEFAULT_ASSET_AMOUNT_MAX, parent=self, min_amount=1)
        self.amount_e.setText('1')
        grid.addWidget(amount_label, 2, 1)
        grid.addWidget(self.amount_e, 2, 2)

        divisions_message = _('Asset Divisions') + '\n\n' \
                            + _('Asset divisions are a number from 0 to 8 and denote how many digits past the decimal point can be used. Once an asset is issued, you cannot decrease this number.')
        divisions_label = HelpLabel(_('Divisions'), divisions_message)

        def on_divisions_change(amount):
            if amount is None:
                return
            assert isinstance(amount, int)
            self.amount_e.divisions = amount
            self.amount_e.is_int = amount == 0
            self.amount_e.min_amount = Decimal('1' if amount == 0 else f'0.{"".join("0" for i in range(amount - 1))}1')
            self.amount_e.numbify()
            self.amount_e.update()

        self.divisions_e = AssetAmountEdit(None, 0, 8, parent=self, callback=on_divisions_change)
        self.divisions_e.get_amount
        divisions_width = char_width_in_lineedit() * 2
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
            if len(input) == 0:
                self.associated_data_is_ok = True
                return None
            try:
                if len(input) % 2 == 1 and len(input) > 2:
                    input = input[:-1]
                raw_bytes = bytes.fromhex(input)
                if len(raw_bytes) < 32:
                    return _('Too few bytes for a TXID')
                elif len(raw_bytes) > 32:
                    return _('Too many bytes for a TXID')
                else:
                    self.associated_data_is_ok = True
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
                        return None
                except BaseDecodeError:
                    return _('Failed to parse input')

        grid.addWidget(associated_data_label, 3, 1)
        self.associated_data_e = ValidatedDelayedCallbackEditor(get_asyncio_loop, associated_data_fast_fail, 0.75, lambda: asyncio.sleep(0))
        grid.addWidget(self.associated_data_e.line_edit, 3, 2, 1, 9)
        grid.addWidget(self.associated_data_e.error_button, 3, 11)

        self.payto_e = QLineEdit()
        self.payto_e.setFont(QFont(MONOSPACE_FONT))

        pay_to_msg = (_("The recipient of the new asset.") + "\n\n"
               + _("If a Bitcoin address is entered, the asset (and any created ownership assets) "
                   "will be sent to this address. "
                   "Leave this empty to send to yourself."))
        payto_label = HelpLabel(_('Recieving Address'), pay_to_msg)
        grid.addWidget(payto_label, 4, 1)
        grid.addWidget(self.payto_e, 4, 2, 1, 9)

        vbox = QVBoxLayout(self)
        vbox.addLayout(grid)

class AssetTab(QWidget, MessageBoxMixin, Logger):
    
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.network = window.network

        if self.wallet.is_watching_only():
            self.create_asset_tab = QLabel(_('Watch only wallets cannot create assets'))
            self.create_asset_tab.setAlignment(Qt.AlignCenter)
        else:
            self.create_asset_tab = CreateAssetPanel(self)

        self.info_label = QLabel(_('Select a tab below to view, create, and manage your assets'))
        self.info_label.setAlignment(Qt.AlignCenter)

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.create_asset_tab, read_QIcon("preferences.png"), _('Create'))
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self.info_label)
        vbox.addWidget(self.tabs)
