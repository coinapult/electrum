"""
Author: Coinapult - support@coinapult.com
"""
import decimal
import httplib

import os
import json
import threading
from urllib import urlencode
from PyQt4.QtCore import SIGNAL
from gui.qt import MyTreeWidget
from gui.qt.qrcodewidget import QRCodeWidget

from electrum_gui.qt import HelpButton, EnterButton
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from PyQt4.QtGui import QMessageBox, QApplication, QPushButton, QComboBox, QDialog, QGridLayout, QLabel, QLineEdit, \
    QCheckBox, QWidget, QHeaderView
from electrum.bitcoin import is_valid
from lib.coinapult import CoinapultClient, CoinapultError

LOCK_ACTIONS = ['Lock', 'Unlock']
LOCKS_CURRENCIES = ['USD', 'EUR', 'GBP', 'XAU', 'XAG']


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
        self.parent.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
        self.is_running = False

    def stop(self):
        self.is_running = False

    def refresh_locks_balances(self):
        try:
            bals = self.client.accountInfo(balanceType='locks', locksAsBTC=True)
            if bals and 'balances' in bals:
                self.parent.config.set_key('Locks_BTC_balance', bals['balances'][0]['amount'], True)

            bals = self.client.accountInfo(balanceType='locks')
            if bals and 'balances' in bals:
                for bal in bals['balances']:
                    if bal['currency'] != 'BTC':
                        self.parent.config.set_key('Locks_%s_balance' % bal['currency'], bal['amount'], True)
        except CoinapultError as ce:
            # TODO: this isn't really something to bother the user about, it is probably just a bad internet connection
            print ce
            return

    def run(self):
        self.is_running = True
        while self.is_running:
            self.query_balances.clear()
            self.refresh_locks_balances()
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
        self.gui.main_window.connect(self.gui.main_window, SIGNAL("refresh_locks_balances()"),
                                     self.gui.main_window.update_status)

    @hook
    def get_locks_BTC_balance(self, r):
        bals = self.locks_BTC_balance()
        r[0] = bals

    @hook
    def load_wallet(self, wallet):
        self.wallet = wallet

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

    def locks_BTC_balance(self):
        return self.config.get('Locks_BTC_balance', 0)

    def locks_balances(self):
        bals = {}
        for cur in LOCKS_CURRENCIES:
            bals[cur] = self.config.get('Locks_%s_balance' % cur, 0)
        return bals

    def fullname(self):
        return 'Coinapult Locks'

    def description(self):
        return _("Coinapult's Locks service lets users tie the value of their bitcoins to USD, EUR, GBP, "
                 "gold or silver.")

    def create_locks_tab(self):
        def on_change_action(act):
            action = LOCK_ACTIONS[act]
            if action != self.config.get('Locks_action', "Lock"):
                self.config.set_key('Locks_action', action, True)

        def on_change_currency(cur):
            if cur != self.config.get('Locks_currency', "USD"):
                self.config.set_key('Locks_currency', LOCKS_CURRENCIES[cur], True)

        def on_btc_amount_change(amount):
            if amount != self.config.get('Locks_amount', 0):
                self.config.set_key('Locks_amount', str(amount), True)

        w = QWidget()
        grid = QGridLayout(w)

        row = 0

        grid.addWidget(QLabel(_('Locks by Coinapult')), row, 0)
        # row += 1
        grid.addWidget(QLabel(_('Eliminate price volatility by Locking bitcoin to a stable asset.')), row, 1)
        row += 1
        locks_bals = self.locks_balances()
        grid.addWidget(QLabel(_('Locks balances')), row, 0)
        for cur in LOCKS_CURRENCIES:
            if cur == 'XAU':
                disp_cur = 'oz of Gold'
            elif cur == 'XAG':
                disp_cur = 'oz of Silver'
            else:
                disp_cur = cur
            grid.addWidget(QLabel(_('%s %s' % (locks_bals[cur], disp_cur))), row, 1)
            row += 1
        grid.addWidget(QLabel(_('Estimated Total BTC Value')), row, 0)
        grid.addWidget(QLabel(_('%s BTC' % self.locks_BTC_balance())), row, 1)
        row += 1

        grid.addWidget(QLabel(_('What would you like to do?')), row, 0)
        combo_action = QComboBox()
        combo_action.currentIndexChanged.connect(on_change_action)
        combo_action.addItems(LOCK_ACTIONS)
        grid.addWidget(combo_action, row, 1)
        row += 1

        grid.addWidget(QLabel(_('Lock to which asset?')), row, 0)
        combo_currency = QComboBox()
        combo_currency.currentIndexChanged.connect(on_change_currency)
        combo_currency.addItems(LOCKS_CURRENCIES)
        grid.addWidget(combo_currency, row, 1)
        row += 1

        grid.addWidget(QLabel(_('How much in BTC?')), row, 0)
        btc_amount_edit = QLineEdit('0')
        btc_amount_edit.textChanged.connect(on_btc_amount_change)
        grid.addWidget(btc_amount_edit, row, 1)
        row += 1

        quote_button = QPushButton(_('Get Quote'))
        quote_button.clicked.connect(self.get_quote)
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

    def get_quote(self):
        if self.locks_action() == 'Lock':
            try:
                lock = self.client.lock(amount=float(self.locks_amount()), currency=self.locks_currency())
                print lock
                return self.lock_confirm_dialog(lock)
            except CoinapultError as ce:
                # TODO: raise warning message
                print ce
        else:
            address = None
            for addr in self.wallet.addresses():
                u, used = self.wallet.is_used(addr)
                if not used:
                    address = addr
                    break
            print address
            try:
                unlock = self.client.unlock(amount=0, outAmount=self.locks_amount(), currency=self.locks_currency(), address=address)
                print unlock
                return self.unlock_confirm_dialog(unlock, address=address)
            except CoinapultError as ce:
                # TODO: raise warning message
                print ce
        #TODO: raise warning message

    def lock_confirm_dialog(self, lock):
        def lock_clicked():
            message = "Lock %s %s for cost of %s_BTC" % (
                lock['out']['expected'], lock['out']['currency'],
                lock['in']['expected'])
            self.gui.main_window.pay_from_URI("bitcoin:%s?amount=%s&message=%s" % (lock['address'],
                                                                                   lock['in']['expected'],
                                                                                   message))
            self.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
            d.accept()
            pass

        d = QDialog()
        d.setWindowTitle("Confirm Lock")
        layout = QGridLayout(d)

        row = 0
        layout.addWidget(QLabel(_('Lock %s %s for a cost of %s BTC?' % (lock['out']['expected'], lock['out']['currency'],
                                                                        lock['in']['expected']))), row, 0)
        layout.addWidget(QLabel(_('Exchange rate: %s' % lock['quote']['bid'])), row, 1)
        row += 1

        layout.addWidget(QLabel(_("If you wish to complete this Lock, please click 'Lock', then send %s BTC to "
                                  "%s" % (lock['in']['expected'], lock['address']))), row, 0)
        row += 1

        lock_button = QPushButton(_("Lock"))
        lock_button.clicked.connect(lock_clicked)
        layout.addWidget(lock_button, row, 1)

        if d.exec_():
            return True
        else:
            return False

    def unlock_confirm_dialog(self, unlock, address):
        def unlock_clicked():
            try:
                self.client.unlockConfirm(transaction_id=unlock['transaction_id'])
                self.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
                d.accept()
            except CoinapultError as ce:
                # TODO: raise alert
                print ce

        d = QDialog()
        d.setWindowTitle("Confirm Unlock")
        layout = QGridLayout(d)

        row = 0
        layout.addWidget(QLabel(_('Unlock %s %s and reclaim %s BTC?' % (unlock['in']['expected'], unlock['in']['currency'],
                                                                        unlock['out']['expected']))), row, 0)
        layout.addWidget(QLabel(_('Exchange rate: %s' % unlock['quote']['ask'])), row, 1)
        row += 1

        layout.addWidget(QLabel(_("If you wish to complete this Unlock, please click 'Unlock' below, then we will send %s BTC to "
                                  "%s" % (unlock['out']['expected'], address))), row, 0)
        row += 1

        unlock_button = QPushButton(_("Unlock"))
        unlock_button.clicked.connect(unlock_clicked)
        layout.addWidget(unlock_button, row, 1)

        if d.exec_():
            return True
        else:
            return False
