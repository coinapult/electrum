"""
Author: Coinapult - support@coinapult.com
"""
import decimal
import httplib

import os
import json
import threading
from PyQt4.QtCore import SIGNAL
from gui.qt import MyTreeWidget
from gui.qt.qrcodewidget import QRCodeWidget

from electrum_gui.qt import HelpButton, EnterButton
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from PyQt4.QtGui import QMessageBox, QApplication, QPushButton, QComboBox, QDialog, QGridLayout, QLabel, QLineEdit, \
    QCheckBox, QWidget, QHeaderView
from lib.coinapult import CoinapultClient, CoinapultError


class Balance_updater(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        if hasattr(self.parent, 'client'):
            self.client = self.parent.client
        else:
            self.client = CoinapultClient({'key': self.parent.api_key(), 'secret': self.parent.api_secret()})
        self.lock = threading.Lock()
        self.query_balances = threading.Event()
        self.parent.gui.main_window.emit(SIGNAL("refresh_locks_balance()"))
        self.is_running = False

    def stop(self):
        self.is_running = False

    def refresh_locks_balance(self):
        bals = self.client.accountInfo(balanceType='locks', locksAsBTC=True)
        if bals and 'balances' in bals:
            self.parent.config.set_key('Locks_balances', bals['balances'][0]['amount'], True)

    def run(self):
        self.is_running = True
        while self.is_running:
            self.query_balances.clear()
            self.refresh_locks_balance()
            self.query_balances.wait(90)


class Plugin(BasePlugin):

    button_label = _("Coinapult Locks")

    def __init__(self, config, name):
        BasePlugin.__init__(self, config, name)
        self.client = CoinapultClient(credentials={'key': self.api_key(), 'secret': self.api_secret()})
        self.balance_updater = None
        self.gui = None

    @hook
    def init_qt(self, gui):
        self.gui = gui
        if not self.agreed_tos() or not self.api_key() or not self.api_secret():
            if self.settings_dialog():
                self.enable()
                return True
            else:
                self.disable()
                return False
        else:
            self.gui.main_window.tabs.addTab(self.create_locks_tab(), "Locks")

        self.btc_rate = decimal.Decimal("0.0")
        if self.balance_updater is None:
            self.balance_updater = Balance_updater(self)
            self.balance_updater.start()
            self.gui.balance_updater = self.balance_updater
            self.gui.main_window.update_status()
        self.gui.main_window.connect(self.gui.main_window, SIGNAL("refresh_locks_balances()"),
                                     self.gui.main_window.update_status)

    @hook
    def get_locks_balances_string(self, r):
        bals = self.locks_balances()
        r[0] = " [~%s BTC Locked]" % bals

    def api_key(self):
        return self.config.get("plugin_coinapult_locks_api_key")

    def api_secret(self):
        return self.config.get("plugin_coinapult_locks_api_secret")

    def agreed_tos(self):
        return self.config.get("plugin_coinapult_locks_tos", False)

    def locks_action(self):
        return self.config.get('Locks_action', "Lock")

    def locks_currency(self):
        return self.config.get('Locks_currency', "USD")

    def locks_amount(self):
        return self.config.get('Locks_amount', 0)

    def locks_balances(self):
        return self.config.get('Locks_balances', 0)

    def fullname(self):
        return 'Coinapult Locks'

    def description(self):
        return _("Coinapult's Locks service lets users tie the value of their bitcoins to USD, EUR, GBP, "
                 "gold or silver.")

    def create_locks_tab(self):
        def on_change_action(action):
            if action != self.config.get('Locks_action', "Lock"):
                self.config.set_key('Locks_action', str(action), True)

        def on_change_currency(cur):
            if cur != self.config.get('Locks_currency', "USD"):
                self.config.set_key('Locks_currency', str(cur), True)

        def on_btc_amount_change(amount):
            if amount != self.config.get('Locks_amount', 0):
                self.config.set_key('Locks_amount', amount, True)

        def submit_to_coinapult():
            if self.locks_action() == 'Lock':
                self.client.lock()
            else:
                self.client.unlock()

        w = QWidget()
        grid = QGridLayout(w)
        grid.setColumnMinimumWidth(3, 400)
        grid.setColumnStretch(5, 1)

        row = 0

        # TODO: Locks GUI goes here
        grid.addWidget(QLabel(_('Locks by Coinapult')), row, 0)
        # row += 1
        grid.addWidget(QLabel(_('Eliminate price volatility by Locking bitcoin to a stable asset.')), row, 1)
        row += 1

        grid.addWidget(QLabel(_('What would you like to do?')), row, 0)
        combo_action = QComboBox()
        combo_action.currentIndexChanged.connect(on_change_currency)
        combo_action.addItems(['Lock', 'Unlock'])
        grid.addWidget(combo_action, row, 1)
        row += 1

        grid.addWidget(QLabel(_('Lock to which asset?')), row, 0)
        combo_currency = QComboBox()
        combo_currency.currentIndexChanged.connect(on_change_currency)
        combo_currency.addItems(['USD', 'EUR', 'GBP', 'XAU', 'XAG'])
        grid.addWidget(combo_currency, row, 1)
        row += 1

        grid.addWidget(QLabel(_('How much in BTC?')), row, 0)
        btc_amount_edit = QLineEdit('0')
        btc_amount_edit.textChanged.connect(on_btc_amount_change)
        grid.addWidget(btc_amount_edit, row, 1)
        row += 1

        quote_button = QPushButton(_('Get Quote'))
        quote_button.clicked.connect(submit_to_coinapult)
        grid.addWidget(quote_button, row, 1)

        return w

    def enable(self):
        self.set_enabled(True)
        return True

    def disable(self):
        length = self.gui.main_window.tabs.count()
        for i in range(0, length):
            if self.gui.main_window.tabs.tabText(i) == "Locks":
                self.gui.main_window.tabs.removeTab(i)

        self.set_enabled(False)
        return True

    def is_available(self):
        return True

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        def check_for_api_key(api_key):
            if api_key and len(api_key) > 12:
                self.config.set_key("plugin_coinapult_locks_api_key", str(api_key))

        def check_for_api_secret(api_secret):
            if api_secret and len(api_secret) > 12:
                self.config.set_key("plugin_coinapult_locks_api_secret", str(api_secret))

        def ok_clicked():
            check_for_api_key(self.api_key_edit.text())
            check_for_api_secret(self.api_secret_edit.text())
            if self.agreed_tos():
                d.accept()
            else:
                self.disable()
                return False

        def on_change_tos(checked):
            if checked:
                self.config.set_key('plugin_coinapult_locks_tos', 'checked')
            else:
                self.config.set_key('plugin_coinapult_locks_tos', 'unchecked')

        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Coinapult API key: ')), 0, 0)
        self.api_key_edit = QLineEdit(self.api_key())
        self.api_key_edit.textChanged.connect(check_for_api_key)
        layout.addWidget(self.api_key_edit, 0, 1, 1, 2)

        layout.addWidget(QLabel(_('Coinapult API secret: ')), 1, 0)
        self.api_secret_edit = QLineEdit()
        self.api_key_edit.textChanged.connect(check_for_api_secret)
        layout.addWidget(self.api_secret_edit, 1, 1, 1, 2)

        layout.addWidget(QLabel(_("Do you agree to Coinapult's Terms of Service (https://coinapult.com/terms)?: ")), 2, 0)
        tos_checkbox = QCheckBox()
        tos_checkbox.setEnabled(True)
        tos_checkbox.setChecked(self.config.get('plugin_coinapult_locks_tos', 'unchecked') != 'unchecked')
        tos_checkbox.stateChanged.connect(on_change_tos)
        layout.addWidget(tos_checkbox, 2, 1)

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(lambda: ok_clicked())
        layout.addWidget(ok_button, 3, 1)

        if d.exec_():
          return True
        else:
          return False
