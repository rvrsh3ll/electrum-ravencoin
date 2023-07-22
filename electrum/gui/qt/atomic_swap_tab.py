from collections import defaultdict
from typing import TYPE_CHECKING, List, Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QSizePolicy, QWidget, QTabWidget, QHBoxLayout, QToolButton, QTextEdit

from electrum import constants
from electrum.bitcoin import opcodes, address_to_scripthash
from electrum.logging import Logger
from electrum.i18n import _
from electrum.transaction import PartialTransaction, Transaction, script_GetOp, Sighash, TxOutpoint, PartialTxOutput, PartialTxInput
from electrum.util import format_satoshis

from .confirm_tx_dialog import ConfirmTxDialog
from .my_treeview import MyMenu
from .util import MessageBoxMixin, read_QIcon, EnterButton, ColorScheme

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class DummySearchableList:
    def filter(self, x):
        pass

class RedeemSwapWidget(QWidget, Logger):
    input_info_signal = pyqtSignal(str, str, bool)

    def __init__(self, parent: 'AtomicSwapTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent

        hbox = QHBoxLayout(self)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Signed Partial') + ':'))
        self.input = QTextEdit()
        self.input.textChanged.connect(self._parse_psbt)
        vbox.addWidget(self.input)
        self.button = EnterButton(_('Redeem...'), self._redeem)
        vbox.addWidget(self.button)
        hbox.addLayout(vbox, stretch=1)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Transaction Information') + ':'))
        vbox.addWidget(QLabel(_('You pay') + ':'))
        self.pay_edit = QTextEdit()
        self.pay_edit.setReadOnly(True)
        vbox.addWidget(self.pay_edit)
        vbox.addWidget(QLabel(_('You receive') + ':'))
        self.receive_edit = QTextEdit()
        self.receive_edit.setReadOnly(True)
        vbox.addWidget(self.receive_edit)
        hbox.addLayout(vbox, stretch=1)

        self.current_transaction = None
        self.current_input_amounts = None
        self.input_info_signal.connect(self._update_inputs)

    def _update_inputs(self, tx_hash: str, input_text: str, error: bool):
        if not self.current_transaction or self.current_transaction.txid() != tx_hash:
            return
        self.receive_edit.setText(input_text)
        if error:
            self.receive_edit.setStyleSheet(ColorScheme.RED.as_stylesheet(True))
        else:
            self.button.setEnabled(True)

    def update(self):
        self._parse_psbt()

    def _parse_psbt(self):
        tx_hex = self.input.toPlainText()
        self.input.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet(True))
        self.receive_edit.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet(True))
        self.pay_edit.clear()
        self.receive_edit.clear()
        self.current_transaction = None
        self.current_input_amounts = None
        self.button.setEnabled(False)
        if not tx_hex:
            return
        try:
            self.current_transaction = tx = Transaction(tx_hex)
            inputs = tx.inputs()
            outputs = tx.outputs()
            if not inputs:
                raise Exception('No inputs')
            if len(inputs) != len(outputs):
                raise Exception('inputs and outputs are not 1-1')
            prevouts = []  # type: List[TxOutpoint]
            for input_i, input in enumerate(inputs):
                # Do a light check for p2pkh/p2pk and p2sh
                if not input.script_sig:
                    raise Exception('Missing input script sig')
                ops = [op for op in script_GetOp(input.script_sig)]
                if ops[0][0] == opcodes.OP_0:
                    # p2sh
                    for op_i, op in enumerate(ops[1:]):
                        if op[1][-1] != Sighash.SINGLE | Sighash.ANYONECANPAY:
                            raise Exception(f'input {input_i} (p2sh) signature {op_i} is not a SINGLE|ANYONECANPAY sig')
                else:
                    # p2pk/h
                    if ops[0][1][-1] != Sighash.SINGLE | Sighash.ANYONECANPAY:
                        raise Exception(f'input {input_i} (p2pk/h) is not a SINGLE|ANYONECANPAY sig')
                prevouts.append(input.prevout)

            if not self.parent.window.network:
                self.receive_edit.setText(_('Unknown (no network connection)'))
            else:
                self.receive_edit.setText(_('Loading...'))

                async def get_data_on_prevouts():
                    fail = False
                    pay_amounts = defaultdict(int)
                    vin_values = []
                    redeemed_check = []
                    for outpoint in prevouts:
                        try:
                            raw_tx = await self.parent.window.network.get_transaction(outpoint.txid.hex())
                            vin_tx = Transaction(raw_tx)
                            output = vin_tx.outputs()[outpoint.out_idx]
                            pay_amounts[output.asset] += output.asset_aware_value()
                            vin_values.append((output.asset, output.asset_aware_value()))

                            scripthash = address_to_scripthash(output.address)
                            unspent_list = await self.parent.window.network.listunspent_for_scripthash(scripthash, asset=output.asset or False)
                            for unspent in unspent_list:
                                if unspent['tx_hash'] == outpoint.txid.hex() and unspent['tx_pos'] == outpoint.out_idx:
                                    redeemed_check.append(False)
                                    break
                            else:
                                redeemed_check.append(True)
                                fail = True
                        except Exception as e:
                            recieve_text = _('Error getting transaction from the network') + ':\n' + repr(e)
                            break
                    else:
                        self.current_input_amounts = vin_values
                        recieve_text = '\n'.join((f'{format_satoshis(v, num_zeros=1)} {k}' if k else self.parent.window.config.format_amount_and_units(v)) + (f' (Already Redeemed)' if redeemed else '')
                                                 for redeemed, (k, v) in zip(redeemed_check, pay_amounts.items()) if v)
                    self.input_info_signal.emit(tx.txid(), recieve_text, fail)

                self.parent.window.network.run_from_another_thread(get_data_on_prevouts())

            pay_amounts = defaultdict(int)
            for output in outputs:
                pay_amounts[output.asset] += output.asset_aware_value()
            pay_text = '\n'.join(f'{format_satoshis(v, num_zeros=1)} {k}' if k else self.parent.window.config.format_amount_and_units(v) for k, v in pay_amounts.items() if v)
            pay_text += '\n' + _('All transaction fees')
            self.pay_edit.setText(pay_text)

        except Exception as e:
            self.logger.info(f'Failed to parse transaction: {e}')
            self.input.setStyleSheet(ColorScheme.RED.as_stylesheet(True))

    def _redeem(self):
        if not self.current_input_amounts or not self.current_transaction:
            return
        
        additional_inputs = []  # type: List[PartialTxInput]
        for input, (asset, amount) in zip(self.current_transaction.inputs(), self.current_input_amounts):
            p_in = PartialTxInput.from_txin(input, strip_witness=False)
            p_in._trusted_asset = asset
            p_in._trusted_value_sats = amount
            p_in._for_swap = True
            additional_inputs.append(p_in)
        
        psbt = PartialTransaction.from_tx(self.current_transaction)
        outputs_to_pay = psbt.outputs()

        def make_tx(fee_est, *, confirmed_only=False):
            tx = self.parent.wallet.make_unsigned_transaction(
                coins=self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                outputs=outputs_to_pay,
                fixed_inputs=additional_inputs,
                fee=fee_est,
                rbf=False,
            )

            for input in additional_inputs:
                tx._inputs.remove(input)
            for input in reversed(additional_inputs):
                tx._inputs.insert(0, input)
            for output in outputs_to_pay:
                tx._outputs.remove(output)
            for output in reversed(outputs_to_pay):
                tx._outputs.insert(0, output)
            tx.locktime = self.current_transaction.locktime
            tx.version = self.current_transaction.version

            return tx
        
        output_amounts_to_pay = defaultdict(int)
        for output in outputs_to_pay:
            output_amounts_to_pay[output.asset] += output.asset_aware_value()

        conf_dlg = ConfirmTxDialog(window=self.parent.window, make_tx=make_tx, output_value=output_amounts_to_pay, allow_edit_locktime=False)
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
        
        self.input.clear()
        self._parse_psbt()

    def get_text_not_enough_funds_mentioning_frozen(self) -> str:
        text = _("Not enough funds")
        frozen_str = self.get_frozen_balance_str()
        if frozen_str:
            text += " ({} {})".format(
                frozen_str, _("are frozen")
            )
        return text

    def get_frozen_balance_str(self) -> Optional[str]:
        frozen_bal = sum(self.parent.wallet.get_frozen_balance())
        if not frozen_bal:
            return None
        return self.parent.window.format_amount_and_units(frozen_bal)


class AtomicSwapTab(QWidget, MessageBoxMixin, Logger):
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.network = window.network

        self.redeem_tab = RedeemSwapWidget(self)

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.redeem_tab, read_QIcon('redeem.png'), _('Redeem'))
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        vbox = QVBoxLayout(self)
        vbox.addWidget(self.tabs)

        self.searchable_list = DummySearchableList()
        
    def update(self):
        self.redeem_tab.update()
        super().update()