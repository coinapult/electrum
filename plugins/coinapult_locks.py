"""
Author: Coinapult - support@coinapult.com
"""
import decimal
import httplib

import os
import threading
from PyQt4.QtCore import SIGNAL

from electrum_gui.qt import EnterButton, WaitingDialog
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from PyQt4.QtGui import QMessageBox, QApplication, QPushButton, QComboBox, QDialog, QGridLayout, QLabel, QLineEdit, \
    QCheckBox, QWidget, QHeaderView, QSizePolicy, QTextEdit, QPlainTextEdit
from electrum.bitcoin import is_valid
from lib.coinapult import CoinapultClient, CoinapultError, CoinapultErrorECC

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
            authMethod = self.config.get('coinapult_auth_method', 'ECC')
            if authMethod == 'REST':
                self.client = CoinapultClient(credentials={'key': self.parent.api_key(),
                                                           'secret': self.parent.api_secret()})
            else:
                # TODO should this be moved to the wallet?
                ecc_pub = self.config.get('coinapult_ecc_public', '')
                ecc_priv = self.config.get('coinapult_ecc_private', '')
                try:
                    self.client = CoinapultClient(ecc={'pubkey': ecc_pub, 'privkey': ecc_priv}, authmethod='ecc')
                except (CoinapultError, CoinapultErrorECC):
                    self.client = None
        self.lock = threading.Lock()
        self.query_balances = threading.Event()
        # self.parent.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
        self.is_running = False

    def stop(self):
        self.is_running = False

    def refresh_locks_balances(self):
        try:
            bals = self.client.accountInfo(balanceType='locks', locksAsBTC=True)
            if bals and 'balances' in bals:
                if len(bals['balances']) > 0:
                    self.parent.config.set_key('Locks_BTC_balance', bals['balances'][0]['amount'], True)
                else:
                    self.parent.config.set_key('Locks_BTC_balance', 0, True)

            bals = self.client.accountInfo(balanceType='locks')
            if bals and 'balances' in bals:
                for cur in LOCKS_CURRENCIES:
                    found = False
                    for bal in bals['balances']:
                        if bal['currency'] == cur:
                            found = True
                            self.parent.config.set_key('Locks_%s_balance' % bal['currency'], bal['amount'], True)
                    if not found:
                        self.parent.config.set_key('Locks_%s_balance' % cur, 0, True)

            self.parent.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
        except (CoinapultError, CoinapultErrorECC) as ce:
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
        authMethod = self.config.get('coinapult_auth_method', 'ECC')
        if authMethod == 'REST':
            self.client = CoinapultClient(credentials={'key': self.api_key(), 'secret': self.api_secret()})
        else:
            #TODO should this be moved to the wallet?
            ecc_pub = self.config.get('coinapult_ecc_public', '')
            ecc_priv = self.config.get('coinapult_ecc_private', '')
            try:
                self.client = CoinapultClient(ecc={'pubkey': ecc_pub, 'privkey': ecc_priv}, authmethod='ecc')
            except:
                self.client = None
                QMessageBox.warning(None, _('Coinapult Connection failed'),
                                    _('Failed to connect to Coinapult. Locks disabled for this session.'), _('OK'))
                self.disable()
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
        self.gui.main_window.connect(self.gui.main_window, SIGNAL("refresh_locks_balances()"),
                                     self.update_locks_bal_display)

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

    def update_locks_bal_display(self):
        lock_bals = self.locks_balances()
        print lock_bals
        row = 1
        for cur in LOCKS_CURRENCIES:
            if cur == 'XAU':
                disp_cur = 'oz of Gold'
            elif cur == 'XAG':
                disp_cur = 'oz of Silver'
            else:
                disp_cur = cur
            widg = self.tabLayout.itemAtPosition(row, 1)
            widg.widget().setText('%s %s' % (lock_bals[cur], disp_cur))
            row += 1
        widg = self.tabLayout.itemAtPosition(row, 1)
        widg.widget().setText('%s BTC' % self.locks_BTC_balance())

    def on_change_action(self, act):
        action = LOCK_ACTIONS[act]
        if action != self.config.get('Locks_action', "Lock"):
            self.config.set_key('Locks_action', action, True)

    def create_locks_tab(self):
        def on_change_currency(cur):
            if cur != self.config.get('Locks_currency', "USD"):
                self.config.set_key('Locks_currency', LOCKS_CURRENCIES[cur], True)

        def on_btc_amount_change(amount):
            if amount != self.config.get('Locks_amount', 0):
                self.config.set_key('Locks_amount', str(amount), True)

        def get_quote():
            def get_lock():
                try:
                    lock = self.client.lock(amount=float(self.locks_amount()), currency=self.locks_currency())
                    print lock
                    return lock
                except (CoinapultError, CoinapultErrorECC) as ce:
                    QMessageBox.warning(None, _('Lock Failed'),
                                        _('Lock action failed due to reason: %s') % (ce), _('OK'))
                    print ce

            def get_unlock():
                self.unlock_address = None
                for addr in self.wallet.addresses():
                    u, used = self.wallet.is_used(addr)
                    if not used and u == 0:
                        self.unlock_address = addr
                        break
                try:
                    unlock = self.client.unlock(amount=0, outAmount=self.locks_amount(), currency=self.locks_currency(),
                                                address=self.unlock_address)
                    return unlock
                except (CoinapultError, CoinapultErrorECC) as ce:
                    QMessageBox.warning(None, _('Unlock Failed'),
                                        _('Unlock action failed due to reason: %s') % (ce), _('OK'))
                    print ce

            self.quote_button.setDisabled(True)
            if self.locks_action() == 'Lock':
                self.waiting_dialog = WaitingDialog(w, 'Requesting Lock Quote',
                                                    get_lock, self.lock_confirm_dialog)
                self.waiting_dialog.start()
            else:
                self.waiting_dialog = WaitingDialog(w, 'Requesting Unlock Quote',
                                                    get_unlock, self.unlock_confirm_dialog)
                self.waiting_dialog.start()

        w = QWidget()
        self.tabLayout = QGridLayout(w)

        self.tabLayout.addWidget(QLabel(_('Locks by Coinapult')), 0, 0)
        self.tabLayout.addWidget(QLabel(_('Eliminate price volatility by Locking bitcoin to a stable asset.')), 0, 1)
        self.tabLayout.addWidget(QLabel(_('Locks balances')), 1, 0)

        row = 1
        for cur in LOCKS_CURRENCIES:
            if cur == 'XAU':
                disp_cur = 'oz of Gold'
            elif cur == 'XAG':
                disp_cur = 'oz of Silver'
            else:
                disp_cur = cur
            self.tabLayout.addWidget(QLabel(_('- %s' % disp_cur)), row, 1)
            row += 1

        self.tabLayout.addWidget(QLabel(_('Estimated Total BTC Value')), row, 0)
        self.tabLayout.addWidget(QLabel(_('%s BTC' % self.locks_BTC_balance())), row, 1)

        self.tabLayout.addWidget(QLabel(_('What would you like to do?')), 7, 0)
        combo_action = QComboBox()
        combo_action.currentIndexChanged.connect(self.on_change_action)
        combo_action.addItems(LOCK_ACTIONS)
        self.tabLayout.addWidget(combo_action, 7, 1)

        self.tabLayout.addWidget(QLabel(_('Which asset?')), 8, 0)
        combo_currency = QComboBox()
        combo_currency.currentIndexChanged.connect(on_change_currency)
        combo_currency.addItems(LOCKS_CURRENCIES)
        self.tabLayout.addWidget(combo_currency, 8, 1)

        self.tabLayout.addWidget(QLabel(_('How much in BTC?')), 9, 0)
        btc_amount_edit = QLineEdit('0')
        btc_amount_edit.textChanged.connect(on_btc_amount_change)
        self.tabLayout.addWidget(btc_amount_edit, 9, 1)

        self.quote_button = QPushButton(_('Get Quote'))
        self.quote_button.clicked.connect(get_quote)
        self.tabLayout.addWidget(self.quote_button, 10, 1)

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

        def check_for_ecc_pub_key(pub_key):
            if pub_key and len(pub_key) > 12:
                self.config.set_key("coinapult_ecc_public", str(pub_key))

        def check_for_ecc_priv_key(priv_key):
            if priv_key and len(priv_key) > 12:
                self.config.set_key("coinapult_ecc_private", str(priv_key))

        def ok_clicked():
            # check_for_api_key(self.api_key_edit.text())
            # check_for_api_secret(self.api_secret_edit.text())
            check_for_ecc_pub_key(self.ecc_pub_key_edit.toPlainText())
            check_for_ecc_priv_key(self.ecc_priv_key_edit.toPlainText())
            if self.agreed_tos():
                d.accept()
            else:
                self.disable()
                return False

        def on_change_auth_method(method):
            if method == 'REST':
                self.config.set_key('coinapult_auth_method', 'REST', True)
            else:
                self.config.set_key('coinapult_auth_method', 'ECC', True)

        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)

        label = QLabel(_("Coinapult's Locks service lets users tie the value of their bitcoins to USD, EUR, GBP, "
                         "gold or silver. This variable bitcoin balance is redeemable for a fixed amount of the asset "
                         "of your choice, on demand.\n\n"
                         "If you already have a Coinapult account, simply paste your ECC credentials below.\n"
                         "Otherwise, click 'Create Account' to see our Terms of Service and generate your ECC keys."))
        label.setWordWrap(True)
        layout.addWidget(label, 0, 1, 1, 2)

        create_account_button = QPushButton(_('Create Account'))
        create_account_button.clicked.connect(self.create_account_dialog)
        layout.addWidget(create_account_button, 2, 1)

        layout.addWidget(QLabel(_('ECC public key')), 3, 0)
        self.ecc_pub_key_edit = QTextEdit(self.config.get("coinapult_ecc_public", ''))
        # self.ecc_pub_key_edit.textChanged.connect(check_for_ecc_pub_key)
        layout.addWidget(self.ecc_pub_key_edit, 3, 1)
        # layout.setRowStretch(2, 3)

        layout.addWidget(QLabel(_('ECC private key')), 4, 0)
        self.ecc_priv_key_edit = QTextEdit("hidden")
        # self.ecc_priv_key_edit.textChanged.connect(check_for_ecc_priv_key)
        layout.addWidget(self.ecc_priv_key_edit, 5, 1)
        # layout.setRowStretch(2, 3)

        ## Rest Layout
        # layout.addWidget(QLabel(_('Coinapult API key: ')), 0, 0)
        # self.api_key_edit = QLineEdit(self.api_key())
        # self.api_key_edit.textChanged.connect(check_for_api_key)
        # layout.addWidget(self.api_key_edit, 0, 1, 1, 2)
        #
        # layout.addWidget(QLabel(_('Coinapult API secret: ')), 1, 0)
        # self.api_secret_edit = QLineEdit("hidden")
        # self.api_key_edit.textChanged.connect(check_for_api_secret)
        # layout.addWidget(self.api_secret_edit, 1, 1, 1, 2)

        ok_button = QPushButton(_("OK"))
        ok_button.setMaximumWidth(50)
        ok_button.clicked.connect(lambda: ok_clicked())
        layout.addWidget(ok_button, 6, 1)

        if d.exec_():
            return True
        else:
            return False

    def create_account_dialog(self):
        def coinapult_signup():
            try:
                self.client.createAccount(createLocalKeys=True, changeAuthMethod=True)
                self.client.activateAccount(agree=True)
            except (CoinapultError, CoinapultErrorECC) as ce:
                QMessageBox.warning(None, _("Unable to create Coinapult account because %s" % str(ce), _("OK")))

        def signup_done(result):
            self.ca_ok_button.setDisabled(False)
            self.config.set_key("coinapult_ecc_public", str(self.client.ecc_pub_pem), True)
            self.ecc_pub_key_edit.setText(self.client.ecc_pub_pem)
            self.config.set_key("coinapult_ecc_private", str(self.client.ecc['privkey'].to_pem()), True)
            self.ecc_priv_key_edit.setText(str(self.client.ecc['privkey'].to_pem()))
            self.config.set_key('coinapult_auth_method', 'ECC', True)
            d.accept()

        def on_change_tos(checked):
            if checked:
                self.config.set_key('plugin_coinapult_locks_tos', 'checked')
            else:
                self.config.set_key('plugin_coinapult_locks_tos', 'unchecked')

        def ok_clicked():
            if self.agreed_tos():
                self.ca_ok_button.setDisabled(True)
                self.waiting_dialog = WaitingDialog(d, 'Creating your Coinapult account. One moment please...',
                                                    coinapult_signup, signup_done)
                self.waiting_dialog.start()

        d = QDialog()
        d.setWindowTitle("Create Coinapult Account")
        layout = QGridLayout(d)

        # lable = None
        layout.addWidget(
            QLabel(_('Creating your Coinapult account. This will overwrite any Coinapult API keys '
                    'in your wallet.\n\nIf you do not have backups, this will lock you out of your ' # TODO This isn't actually stored in the wallet yet...
                    'account!')), 0, 0)

        text_edit = QPlainTextEdit()
        text = open(os.path.dirname(__file__) + '/lib/TERMS.txt').read()
        text_edit.setPlainText(text)
        layout.addWidget(text_edit, 1, 0)
        layout.setRowStretch(1, 4)

        layout.addWidget(QLabel(_("Do you agree to Coinapult's Terms of Service (https://coinapult.com/terms)?: ")), 3, 0)
        tos_checkbox = QCheckBox()
        tos_checkbox.setEnabled(True)
        tos_checkbox.setChecked(self.config.get('plugin_coinapult_locks_tos', 'unchecked') != 'unchecked')
        tos_checkbox.stateChanged.connect(on_change_tos)
        layout.addWidget(tos_checkbox, 3, 1)

        self.ca_ok_button = QPushButton(_("OK"))
        self.ca_ok_button.clicked.connect(ok_clicked)
        layout.addWidget(self.ca_ok_button, 4, 1)

        if d.exec_():
            return True
        else:
            return False

    def lock_confirm_dialog(self, lock):
        def lock_clicked():
            message = "Lock %s %s for cost of %s BTC" % (
                lock['out']['expected'], lock['out']['currency'],
                lock['in']['expected'])
            self.gui.main_window.pay_from_URI("bitcoin:%s?amount=%s&message=%s" % (lock['address'],
                                                                                   lock['in']['expected'],
                                                                                   message))
            self.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
            d.accept()
            pass

        self.quote_button.setDisabled(False)

        d = QDialog()
        d.setWindowTitle("Confirm Lock")
        layout = QGridLayout(d)

        row = 0
        layout.addWidget(QLabel(_('Lock %s %s for a cost of %s BTC?' % (lock['out']['expected'], lock['out']['currency'],
                                                                        lock['in']['expected']))), row, 0)
        layout.addWidget(QLabel(_('Exchange rate: %s' % lock['quote']['bid'])), row, 1)
        row += 1

        layout.addWidget(QLabel(_("If you wish to complete this Lock, please click 'Lock', then send %s BTC to "
                                  "%s\n\nPlease note that this transaction will take 2 confirmations to complete." %
                                  (lock['in']['expected'], lock['address']))), row, 0)
        row += 1

        lock_button = QPushButton(_("Lock"))
        lock_button.clicked.connect(lock_clicked)
        layout.addWidget(lock_button, row, 1)

        if d.exec_():
            return True
        else:
            return False

    def unlock_confirm_dialog(self, unlock):
        def unlock_clicked():
            try:
                print self.client.unlockConfirm(transaction_id=unlock['transaction_id'])
                self.gui.main_window.emit(SIGNAL("refresh_locks_balances()"))
                d.accept()
            except (CoinapultError, CoinapultErrorECC) as ce:
                QMessageBox.warning(None, _('Unlock Failed'),
                                    _('Unlock action failed due to reason: %s') % (ce), _('OK'))
                print ce

        self.quote_button.setDisabled(False)

        d = QDialog()
        d.setWindowTitle("Confirm Unlock")
        layout = QGridLayout(d)

        row = 0
        layout.addWidget(QLabel(_('Unlock %s %s and reclaim %s BTC?' % (unlock['in']['expected'], unlock['in']['currency'],
                                                                        unlock['out']['expected']))), row, 0)
        layout.addWidget(QLabel(_('Exchange rate: %s' % unlock['quote']['ask'])), row, 1)
        row += 1

        layout.addWidget(QLabel(_("If you wish to complete this Unlock, please click 'Unlock' below, then we will send %s BTC to "
                                  "%s" % (unlock['out']['expected'], self.unlock_address))), row, 0)
        row += 1

        unlock_button = QPushButton(_("Unlock"))
        unlock_button.clicked.connect(unlock_clicked)
        layout.addWidget(unlock_button, row, 1)

        if d.exec_():
            return True
        else:
            return False
