from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QCheckBox, QWidget, QComboBox, QMessageBox

from electrum.logging import Logger

if TYPE_CHECKING:
    from asset_tab import AssetTab

class MakeBroadcastPanel(QWidget, Logger):
    def __init__(self, parent: 'AssetTab'):
        QWidget.__init__(self)
        Logger.__init__(self)

        self.parent = parent