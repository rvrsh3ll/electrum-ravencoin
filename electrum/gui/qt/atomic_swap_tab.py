import asyncio

from collections import defaultdict
from decimal import Decimal
from typing import TYPE_CHECKING, List, Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QLabel, QVBoxLayout, QSizePolicy, QWidget, QTabWidget, QHBoxLayout, QComboBox, QTextEdit

from electrum import constants
from electrum.bitcoin import opcodes, address_to_scripthash, COIN
from electrum.asset import DEFAULT_ASSET_AMOUNT_MAX
from electrum.logging import Logger
from electrum.i18n import _
from electrum.transaction import PartialTransaction, Transaction, script_GetOp, Sighash, TxOutpoint, PartialTxOutput, PartialTxInput, TxInput
from electrum.util import format_satoshis

from .asset_management_panel import AssetAmountEdit
from .confirm_tx_dialog import ConfirmTxDialog
from .util import (MessageBoxMixin, read_QIcon, EnterButton, ColorScheme, NonlocalAssetOrBasecoinSelector, 
                   QHSeperationLine, Buttons, QtEventListener, qt_event_listener, WaitingDialog)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class DummySearchableList:
    def filter(self, x):
        pass

class CreateSwapWidget(QWidget, Logger, MessageBoxMixin, QtEventListener):
    def __init__(self, parent: 'AtomicSwapTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent
        self.want_asset_is_good = True
        self.want_amount_is_good = False
        self.pay_amount_is_good = False

        hbox = QHBoxLayout(self)
        vbox = QVBoxLayout()
        want_label = QLabel(_('I want') + ':')
        def want_asset_name_valid(is_valid: bool):
            self.want_amount_e.update()
            self.want_amount_e.setEnabled(False)
            self.want_asset_is_good = False
            self._maybe_enable_create()

        def want_asset_metadata(input):
            self.want_amount_e.setEnabled(True)
            self.want_asset_is_good = True
            if not input:
                self.want_amount_e.divisions = 8
                self.want_amount_e.max_amount = DEFAULT_ASSET_AMOUNT_MAX
                if input is False:
                    self.want_amount_e.setEnabled(False)
                    self.want_asset_is_good = False
            else:
                self.want_amount_e.divisions = input['divisions']
                self.want_amount_e.max_amount = input['sats_in_circulation']
            self.want_amount_e.is_int = self.want_amount_e.divisions == 0
            self.want_amount_e.min_amount = Decimal('1' if self.want_amount_e.divisions == 0 else f'0.{"".join("0" for i in range(self.want_amount_e.divisions - 1))}1') * COIN
            self.want_amount_e.numbify()
            self.want_amount_e.update()
            self._maybe_enable_create()

        def want_amount_edit(amount: int):
            self.want_amount_is_good = bool(amount)
            self._maybe_enable_create()

        self.want_selector = NonlocalAssetOrBasecoinSelector(parent.window, check_callback=want_asset_name_valid, delayed_check_callback=want_asset_metadata)
        self.want_amount_e = AssetAmountEdit(self.want_selector.short_name, 0, DEFAULT_ASSET_AMOUNT_MAX, min_amount=COIN, callback=want_amount_edit)
        want_amount_layout = QHBoxLayout()
        want_amount_layout.addWidget(QLabel(_('Of amount') + ':'))
        want_amount_layout.addWidget(self.want_amount_e)
        want_amount_layout.addStretch()

        pay_label = QLabel(_('I\'ll pay') + ':')
        
        def pay_amount_edit(amount: int):
            self.pay_amount_is_good = bool(amount)
            self._maybe_enable_create()

        self.pay_selector = QComboBox()
        self.pay_selector.setMaxVisibleItems(10)
        self.pay_selector.setStyleSheet("QComboBox { combobox-popup: 0; }")
        self.current_balance = self.parent.wallet.get_balance(asset_aware=True)
        assets = [constants.net.SHORT_NAME]
        assets.extend(sorted(k for k in self.current_balance.keys() if k))
        self.pay_selector.addItems(assets)
        self.pay_selector.currentIndexChanged.connect(self._on_combo_update)
        
        self.pay_amount_e = AssetAmountEdit(lambda: self.pay_selector.currentText()[:4], 0, DEFAULT_ASSET_AMOUNT_MAX, min_amount=COIN, callback=pay_amount_edit)
        pay_amount_layout = QHBoxLayout()
        pay_amount_layout.addWidget(QLabel(_('Of amount') + ':'))
        pay_amount_layout.addWidget(self.pay_amount_e)
        pay_amount_layout.addStretch()

        self.create_swap = EnterButton(_('Create Swap...'), self._set_up_swap)
        self.create_swap.setEnabled(False)
        self.clear_swap = EnterButton(_('Clear'), self._clear)
        self.clear_swap.setEnabled(False)

        vbox.addWidget(want_label)
        vbox.addWidget(self.want_selector)
        vbox.addLayout(want_amount_layout)
        vbox.addWidget(QHSeperationLine())
        vbox.addWidget(pay_label)
        vbox.addWidget(self.pay_selector)
        vbox.addLayout(pay_amount_layout)
        vbox.addLayout(Buttons(self.create_swap, self.clear_swap))
        vbox.addStretch()
        hbox.addLayout(vbox, stretch=1)

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Signed Partial') + ':'))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output_label = QLabel(_('Swap added to history...'))
        self.output_label.setVisible(False)
        vbox.addWidget(self.output)
        vbox.addWidget(self.output_label)
        hbox.addLayout(vbox, stretch=1)

        self.waiting_for_tx = None
        self.register_callbacks()

    def _on_combo_update(self):
        divisions = 8
        asset = None if self.pay_selector.currentIndex() == 0 else self.pay_selector.currentText()
        if asset:
            metadata_tup = self.parent.wallet.adb.get_asset_metadata(asset)
            divisions = metadata_tup[0].divisions
        balance = sum(self.current_balance[asset])
        self.pay_amount_e.divisions = divisions
        self.pay_amount_e.max_amount = balance
        self.pay_amount_e.is_int = divisions == 0
        self.pay_amount_e.min_amount = Decimal('1' if divisions == 0 else f'0.{"".join("0" for i in range(divisions - 1))}1') * COIN
        self.pay_amount_e.numbify()
        self.pay_amount_e.update()

    def _maybe_enable_create(self):
        self.create_swap.setEnabled(self.pay_amount_is_good and 
                                    self.want_asset_is_good and self.want_amount_is_good)

    def _set_up_swap(self):
        pay_amount = self.pay_amount_e.get_amount()
        pay_asset = None if self.pay_selector.currentIndex() == 0 else self.pay_selector.currentText()

        for utxo in self.parent.wallet.get_spendable_coins():
            if utxo.asset == pay_asset and utxo.value_sats(asset_aware=True) == pay_amount:
                self._create_swap(utxo)
                return
        else:
            msg = _('No unspent transaction outputs found matching the pay parameters.') + '\n' + \
                _('Broadcast a transaction to make one?')
            if self.question(msg, self, _('Preliminary Transaction')):
                new_output_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
                def make_tx(fee_est, *, confirmed_only=False):
                    try:
                        self.parent.wallet.set_reserved_state_of_address(new_output_address, reserved=True)
                        tx = self.parent.wallet.make_unsigned_transaction(
                            coins=self.parent.window.get_coins(nonlocal_only=False, confirmed_only=confirmed_only),
                            outputs=[PartialTxOutput.from_address_and_value(new_output_address, pay_amount, asset=pay_asset)],
                            fee=fee_est,
                            rbf=False,
                        )
                    finally:
                        self.parent.wallet.set_reserved_state_of_address(new_output_address, reserved=False)
                    return tx
                
                # TODO: Figure out a way to do this when allowing tx preview
                conf_dlg = ConfirmTxDialog(window=self.parent.window, make_tx=make_tx, output_value={pay_asset: pay_amount}, allow_preview=False)
                if conf_dlg.not_enough_funds:
                    if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                        text = self.parent.window.get_text_not_enough_funds_mentioning_frozen()
                        self.parent.show_message(text)
                        return
                tx = conf_dlg.run()
                if tx is None:
                    return
                
                def sign_done(success):
                    if success:
                        self.parent.window.broadcast_or_show(tx)
                        if tx.is_complete():
                            self.pay_amount_e.setEnabled(False)
                            # Mark false for any delayed checks
                            self.want_asset_is_good = False
                            self.want_amount_e.setEnabled(False)
                            self.pay_selector.setEnabled(False)
                            self.want_selector.combo.setEnabled(False)
                            self.want_selector.line_edit.line_edit.setEnabled(False)
                            self.create_swap.setEnabled(False)
                            self.waiting_for_tx = tx.txid()
                            self.output.setText(_('Please wait for the transaction to be successfully broadcast.'))

                self.parent.window.sign_tx(
                    tx,
                    callback=sign_done,
                    external_keypairs=None)

    @qt_event_listener
    def on_event_adb_added_tx(self, adb, tx_hash, tx: Transaction):
        if tx_hash == self.waiting_for_tx:
            pay_amount = self.pay_amount_e.get_amount()
            pay_asset = None if self.pay_selector.currentIndex() == 0 else self.pay_selector.currentText()

            self.waiting_for_tx = None
            self.parent.window.wallet.set_label(tx_hash, _('Preliminary Atomic Swap Transaction'))
            for i, output in enumerate(tx.outputs()):
                if output.asset == pay_asset and output.asset_aware_value() == pay_amount:
                    input = PartialTxInput(prevout=TxOutpoint.from_str(f'{tx_hash}:{i}'))
                    input.utxo = tx
                    self._create_swap(input)
                    return
            else:
                self.show_warning(_('Failed to find the outpoint that matches the pay amount in the new transaction'))
                self._clear()
                
    def _create_swap(self, utxo: PartialTxInput):
        tx = PartialTransaction()

        utxo._fixed_nsequence = True
        utxo.sighash = Sighash.SINGLE | Sighash.ANYONECANPAY
        utxo.nsequence = 0

        my_address = self.parent.wallet.get_single_change_address_for_new_transaction() or \
                        self.parent.wallet.get_receiving_address() # Fallback
        my_amount = self.want_amount_e.get_amount()
        my_asset = self.want_selector.asset
        output = PartialTxOutput.from_address_and_value(my_address, my_amount, asset=my_asset)

        tx.add_inputs([utxo])
        tx.add_outputs([output])

        def print_swap(success):
            if success:
                swap_hex = tx.serialize_to_network()
                self.output.setText(swap_hex)
                self.output_label.setVisible(True)
                self.pay_amount_e.setEnabled(False)
                # Mark false for any delayed checks
                self.want_asset_is_good = False

                self.want_amount_e.setEnabled(False)
                self.pay_selector.setEnabled(False)
                self.want_selector.combo.setEnabled(False)
                self.want_selector.line_edit.line_edit.setEnabled(False)
                self.create_swap.setEnabled(False)
                self.clear_swap.setEnabled(True)

                self.parent.window.set_frozen_state_of_coins([utxo], True)
                self.parent.wallet.set_reserved_state_of_address(my_address, reserved=True)
                self.parent.wallet.set_label(my_address, _('Reserved For Atomic Swap'))

                # TODO: Make this better
                self.parent.wallet.adb.db.my_swaps[tx.txid()] = swap_hex

        self.parent.window.sign_tx(tx, callback=print_swap, external_keypairs=None)

    def _clear(self):
        self.pay_amount_e.setEnabled(True)
        self.want_amount_e.setEnabled(True)
        self.pay_selector.setEnabled(True)
        self.want_selector.combo.setEnabled(True)
        self.want_selector.line_edit.line_edit.setEnabled(False)
        self.create_swap.setEnabled(True)

        self.pay_amount_e.clear()
        self.want_amount_e.clear()
        self.pay_selector.setCurrentIndex(0)
        self.want_selector.combo.setCurrentIndex(0)

        self.clear_swap.setEnabled(False)

        self.output.clear()
        self.output_label.setVisible(False)

    def update(self):
        current_balance = self.parent.wallet.get_balance(asset_aware=True)
        if self.current_balance.keys() != current_balance.keys():
            assets = [constants.net.SHORT_NAME]
            assets.extend(sorted(k for k in current_balance.keys() if k))
            current_text = self.pay_selector.currentText()
            self.pay_selector.clear()
            self.pay_selector.addItems(assets)
            try:
                i = assets.index(current_text)
                self.pay_selector.setCurrentIndex(i)
            except ValueError:
                pass
        self.current_balance = current_balance
        self._on_combo_update()
        super().update()

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
            self.logger.info(f'Failed to parse transaction: {e} ({e.__class__})')
            self.input.setStyleSheet(ColorScheme.RED.as_stylesheet(True))

    def _redeem(self):
        if not self.current_input_amounts or not self.current_transaction:
            return
        
        additional_inputs = []  # type: List[PartialTxInput]
        for input, (asset, amount) in zip(self.current_transaction.inputs(), self.current_input_amounts):
            p_in = PartialTxInput.from_txin(input, strip_witness=False)
            p_in._trusted_asset = asset
            p_in._trusted_value_sats = amount
            p_in._fixed_nsequence = True
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
                text = self.parent.window.get_text_not_enough_funds_mentioning_frozen()
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

class AtomicSwapTab(QWidget, MessageBoxMixin, Logger):
    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.network = window.network

        self.redeem_tab = RedeemSwapWidget(self)
        self.create_tab = CreateSwapWidget(self)

        self.tabs = tabs = QTabWidget(self)
        tabs.addTab(self.redeem_tab, read_QIcon('redeem.png'), _('Redeem'))
        tabs.addTab(self.create_tab, read_QIcon('unconfirmed.png'), _('Create'))
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        vbox = QVBoxLayout(self)
        vbox.addWidget(self.tabs)

        self.searchable_list = DummySearchableList()
        
    def update(self):
        self.redeem_tab.update()
        self.create_tab.update()
        super().update()
    