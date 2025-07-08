import threading
import requests
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.clock import Clock
from kivy.uix.checkbox import CheckBox
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
from plyer import notification

TOKENS = {
    "TRX": {"path": "44'/195'/0'/0/{}", "api": "https://apilist.tronscanapi.com/api/account?address="},
    "BTC": {"path": "44'/0'/0'/0/{}", "api": "https://blockchain.info/rawaddr/"},
    "ETH": {"path": "44'/60'/0'/0/{}", "api": "https://api.ethplorer.io/getAddressInfo/{}?apiKey=freekey"},
    "LTC": {"path": "44'/2'/0'/0/{}", "api": "https://api.blockcypher.com/v1/ltc/main/addrs/{}"},
}

enabled_tokens = {"TRX": True, "BTC": True, "ETH": True, "LTC": True}
log_output = []

class MainScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)

        # Token checkboxes
        token_layout = BoxLayout(size_hint_y=None, height='40dp')
        for token in TOKENS:
            checkbox = CheckBox(active=True)
            checkbox.bind(active=self.toggle_token(token))
            token_layout.add_widget(Label(text=token, size_hint_x=None, width=50))
            token_layout.add_widget(checkbox)
        self.add_widget(token_layout)

        # Button to start scan
        start_btn = Button(text="Запустить сканирование", size_hint_y=None, height='40dp')
        start_btn.bind(on_press=self.start_scan)
        self.add_widget(start_btn)

        # Scrollable log
        self.log_label = Label(text='', size_hint_y=None, halign='left', valign='top')
        self.log_label.bind(texture_size=self.update_height)
        scroll = ScrollView()
        scroll.add_widget(self.log_label)
        self.add_widget(scroll)

    def update_height(self, instance, value):
        self.log_label.height = self.log_label.texture_size[1]

    def toggle_token(self, token_name):
        def toggle(instance, value):
            enabled_tokens[token_name] = value
        return toggle

    def start_scan(self, instance):
        threading.Thread(target=self.worker, daemon=True).start()

    def log(self, text):
        log_output.append(text)
        Clock.schedule_once(lambda dt: self.update_log(), 0)

    def update_log(self):
        self.log_label.text = '\n'.join(log_output[-100:])

    def worker(self):
        mnemo = Mnemonic("english")
        for _ in range(100):
            phrase = mnemo.generate(strength=128)
            self.log(f"[+] Проверка сид-фразы: {phrase}")
            try:
                for token, settings in TOKENS.items():
                    if not enabled_tokens.get(token):
                        continue
                    for i in range(10):  # /0/0 to /0/9
                        priv = bip39_to_private_key(phrase, settings["path"].format(i))
                        addr = private_key_to_address(priv, token)
                        balance = get_balance(addr, token)
                        if balance > 0:
                            self.log(f"[FOUND] {token} | Адрес: {addr} | Баланс: {balance}")
                            save_result(addr, priv, balance, token)
                            send_notification(f"{token} НАЙДЕН", f"{addr}\nБаланс: {balance}")
            except Exception as e:
                self.log(f"[!] Ошибка: {str(e)}")

def bip39_to_private_key(phrase, derivation_path="44'/195'/0'/0/0"):
    seed = Mnemonic.to_seed(phrase, passphrase="")
    bip32_root_key = BIP32Key.fromEntropy(seed)

    for level in derivation_path.split("/"):
        if level.endswith("'"):
            hardened = 0x80000000
            index = int(level[:-1]) + hardened
        else:
            index = int(level)
        bip32_root_key = bip32_root_key.ChildKey(index)
    return bip32_root_key.WalletImportFormat()

def private_key_to_address(priv_key_wif, token):
    sk = SigningKey.from_string(BIP32Key.fromWalletImportFormat(priv_key_wif).k, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey = b'\x04' + vk.to_string()

    if token == "TRX":
        import hashlib
        import base58
        h = hashlib.sha3_256()
        h.update(pubkey)
        addr = b'\x41' + h.digest()[-20:]
        return base58.b58encode_check(addr).decode()
    elif token == "BTC":
        import hashlib
        import base58
        sha256 = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        return base58.b58encode_check(b'\x00' + ripemd160).decode()
    elif token == "ETH":
        from eth_utils import keccak
        eth_addr = keccak(pubkey[1:])[-20:]
        return "0x" + eth_addr.hex()
    elif token == "LTC":
        import hashlib
        import base58
        sha256 = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        return base58.b58encode_check(b'\x30' + ripemd160).decode()
    return "?"

def get_balance(address, token):
    try:
        if token == "TRX":
            r = requests.get(TOKENS[token]["api"] + address)
            return float(r.json().get("balance", 0)) / 1e6
        elif token == "BTC":
            r = requests.get(TOKENS[token]["api"] + address)
            return float(r.json().get("final_balance", 0)) / 1e8
        elif token == "ETH":
            r = requests.get(TOKENS[token]["api"].format(address))
            return float(r.json().get("ETH", {}).get("balance", 0))
        elif token == "LTC":
            r = requests.get(TOKENS[token]["api"].format(address))
            return float(r.json().get("balance", 0)) / 1e8
    except Exception:
        return 0.0
    return 0.0

def save_result(address, priv_key, balance, token):
    with open("/storage/emulated/0/CryptoKeyFinder_Result.txt", "a") as f:
        f.write(f"{token} | {address} | {priv_key} | Баланс: {balance}\n")

def send_notification(title, message):
    notification.notify(title=title, message=message)

class CryptoKeyFinderApp(App):
    def build(self):
        return MainScreen()

if __name__ == '__main__':
    CryptoKeyFinderApp().run()
