from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label

class CryptoApp(App):
    def build(self):
        return BoxLayout(orientation='vertical', children=[
            Label(text="CryptoKeyFinder is running...")
        ])

if __name__ == '__main__':
    CryptoApp().run()
