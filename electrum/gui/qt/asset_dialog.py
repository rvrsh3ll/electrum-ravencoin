from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QScrollArea, QLineEdit, QDialog

from electrum.address_synchronizer import METADATA_UNCONFIRMED, METADATA_UNVERIFIED
from electrum.asset import AssetMetadata
from electrum.i18n import _
from electrum.network import UntrustedServerReturnedError
from electrum.transaction import TxOutpoint
from electrum.util import trigger_callback

from .asset_view_panel import MetadataInfo
from .util import Buttons, CloseButton, MessageBoxMixin, BlockingWaitingDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

class AssetDialog(QDialog, MessageBoxMixin):
    def __init__(self, window: 'ElectrumWindow', asset: str):
        QDialog.__init__(self, parent=window)
        self.setWindowTitle(asset)

        #self.setWindowModality(Qt.NonModal)
        self.asset = asset
        self.ipfs = None
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

        local_metadata = self.wallet.adb.get_asset_metadata(asset)
        type_text = None
        verifier_string_data = None
        verifier_string_text = None
        freeze_data = None
        freeze_text = None
        tag_overrides = None
        association_overrides = None
        if local_metadata is None:
            if not window.network:
                self.window.show_message(_("You are offline."))
                return
            try:
                metadata_data = self.network.run_from_another_thread(
                    self.network.get_asset_metadata(asset))
                
                if not metadata_data:
                    self.window.show_message(_("This asset does not exist."))
                    return
                                
                metadata = AssetMetadata(
                    sats_in_circulation=metadata_data['sats_in_circulation'],
                    divisions = metadata_data['divisions'],
                    reissuable = metadata_data['reissuable'],
                    associated_data = metadata_data['ipfs'] if metadata_data['has_ipfs'] else None
                )

                if metadata.is_associated_data_ipfs:
                    self.ipfs = metadata.associated_data_as_ipfs()
                metadata_sources = (
                    bytes.fromhex(metadata_data['source']['tx_hash']), 
                    bytes.fromhex(metadata_data['source_divisions']['tx_hash']) if 'source_divisions' in metadata_data else None,
                    bytes.fromhex(metadata_data['source_ipfs']['tx_hash']) if 'source_ipfs' in metadata_data else None)
                
                if asset[0] == '$':
                    d = self.network.run_from_another_thread(
                        self.network.get_verifier_string_for_restricted_asset(asset)
                    )
                    if d:
                        verifier_string_data = d

                    d = self.network.run_from_another_thread(
                        self.network.get_freeze_status_for_restricted_asset(asset)
                    )
                    if d:
                        freeze_data = d

                if asset[0] in ('$', '#'):
                    d = self.network.run_from_another_thread(
                        self.network.get_tags_for_qualifier(asset)
                    )
                    if d:
                        tag_overrides = d
                
                if asset[0] == '#':
                    d = self.network.run_from_another_thread(
                        self.network.get_associations_for_qualifier(asset)
                    )
                    if d:
                        association_overrides = d

                if self.window.config.VERIFY_TRANSITORY_ASSET_DATA:
                    async def verify_metadata():
                        tx_to_wait_for = [
                            (metadata_data['source']['tx_hash'], metadata_data['source']['height'])
                        ]
                        if 'source_divisions' in metadata_data:
                            tx_to_wait_for.append((metadata_data['source_divisions']['tx_hash'], metadata_data['source_divisions']['height']))
                        if 'source_ipfs' in metadata_data:
                            tx_to_wait_for.append((metadata_data['source_ipfs']['tx_hash'], metadata_data['source_ipfs']['height']))
                        if verifier_string_data:
                            tx_to_wait_for.append((verifier_string_data['tx_hash'], verifier_string_data['height']))
                        if freeze_data:
                            tx_to_wait_for.append((freeze_data['tx_hash'], freeze_data['height']))
                        if tag_overrides:
                            tx_to_wait_for.extend((item['tx_hash'], item['height']) for item in tag_overrides.values())
                        if association_overrides:
                            tx_to_wait_for.extend((item['tx_hash'], item['height']) for item in association_overrides.values())

                        await self.wallet.adb.verifier.wait_until_transactions_can_be_verified(tx_to_wait_for)
                        await self.wallet.adb.verifier._internal_verify_unverified_asset_metadata(
                            asset,
                            metadata,
                            (TxOutpoint(bytes.fromhex(metadata_data['source']['tx_hash']), metadata_data['source']['tx_pos']), metadata_data['source']['height']),
                            (TxOutpoint(bytes.fromhex(metadata_data['source_divisions']['tx_hash']), metadata_data['source_divisions']['tx_pos']), metadata_data['source_divisions']['height']) if 'source_divisions' in metadata_data else None,
                            (TxOutpoint(bytes.fromhex(metadata_data['source_ipfs']['tx_hash']), metadata_data['source_ipfs']['tx_pos']), metadata_data['source_ipfs']['height']) if 'source_ipfs' in metadata_data else None,
                        )
                        if verifier_string_data:
                            await self.wallet.adb.verifier._internal_verify_unverified_restricted_verifier(
                                asset,
                                verifier_string_data
                            )
                        if freeze_data:
                            await self.wallet.adb.verifier._internal_verify_unverified_restricted_freeze(
                                asset,
                                freeze_data
                            )
                        if tag_overrides:
                            for h160, item in tag_overrides.items():
                                await self.wallet.adb.verifier._internal_verify_unverified_tag_for_qualifier(
                                    asset, h160, item
                                )
                        if association_overrides:
                            for res, item in association_overrides.items():
                                await self.wallet.adb.verifier._internal_verify_unverified_association(
                                    asset, res, item
                                )

                    BlockingWaitingDialog(self.window, _('Verifying Asset Information...'), lambda: self.network.run_from_another_thread(
                        verify_metadata()
                    ))


            except UntrustedServerReturnedError as e:
                self.window.logger.info(f"Error getting info from network: {repr(e)}")
                self.window.show_message(
                    _("Error getting info from network") + ":\n" + e.get_message_for_gui()
                )
                return
            except Exception as e:
                self.window.logger.info(f"Error getting info from network (2): {repr(e)}")
                self.window.show_message(
                    _("Error getting info from network") + ":\n" + repr(e)
                )
                return
        else:
            metadata, metadata_source = local_metadata
            if metadata.is_associated_data_ipfs():
                self.ipfs = metadata.associated_data_as_ipfs()
            if metadata_source == METADATA_UNCONFIRMED:
                type_text = _('UNCONFIRMED')
            elif metadata_source == METADATA_UNVERIFIED:
                type_text = _('NOT VERIFIED!')
            metadata_sources = self.wallet.adb.get_asset_metadata_txids(asset)
            if asset[0] == '$':
                verifier_string_data_tup = self.wallet.adb.get_restricted_verifier_string(asset)
                if verifier_string_data_tup:
                    verifier_string_data, verifier_string_type_id = verifier_string_data_tup
                    if verifier_string_type_id == METADATA_UNCONFIRMED:
                        verifier_string_text = _('UNCONFIRMED')
                    elif verifier_string_type_id == METADATA_UNVERIFIED:
                        verifier_string_text = _('NOT VERIFIED!')

                freeze_data_tup = self.wallet.adb.get_restricted_freeze(asset)
                if freeze_data_tup:
                    freeze_data, freeze_type_id = freeze_data_tup
                    if freeze_type_id == METADATA_UNCONFIRMED:
                        freeze_text = _('UNCONFIRMED')
                    elif freeze_type_id == METADATA_UNVERIFIED:
                        freeze_text = _('NOT VERIFIED!')
        
        self.m = MetadataInfo(self.window)
        self.m.update(asset, type_text, metadata, metadata_sources,
                    verifier_string_text, verifier_string_data, 
                    freeze_text, freeze_data, tag_overrides=tag_overrides, association_overrides=association_overrides)
        
        scroll = QScrollArea()
        scroll.setWidget(self.m)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        vbox.addWidget(self.search_box)
        vbox.addWidget(scroll)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.valid = True

    def closeEvent(self, event):
        self.m.ipfs_viewer.unregister_callbacks()
        if self.ipfs:
            trigger_callback('ipfs_hash_dissociate_asset', self.ipfs, self.asset)
        event.accept()


    def do_search(self, text):
        self.m.address_list.filter(text)

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.ControlModifier and event.key() == Qt.Key_F:
            self.search_box.setHidden(not self.search_box.isHidden())
            if not self.search_box.isHidden():
                self.search_box.setFocus(1)
            else:
                self.do_search('')

        super().keyPressEvent(event)
