[app]
title = CryptoKeyFinder
package.name = cryptokeyfinder
package.domain = org.cryptokeyfinder
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,mnemonic,ecdsa,bip32utils,requests,plyer
orientation = portrait
osx.python_version = 3
fullscreen = 1
android.permissions = INTERNET,FOREGROUND_SERVICE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.ndk_path = 
android.sdk_path = 
android.gradle_dependencies = com.android.support:support-v4:28.0.0
android.archs = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 0
