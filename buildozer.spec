[app]
title = Packet Analyzer
package.name = packetanalyzer
package.domain = org.packetlab
source.dir = .
source.include_exts = py,json
source.exclude_dirs = tests,.github,bin,.buildozer,__pycache__
version = 0.2.0
requirements = python3==3.11.5,hostpython3==3.11.5,kivy==2.3.0
orientation = portrait
fullscreen = 0
services = Proxy:service.py:foreground

android.permissions = INTERNET,FOREGROUND_SERVICE,POST_NOTIFICATIONS
android.api = 33
android.minapi = 24
android.ndk = 25b
android.ndk_api = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.allow_backup = False

[buildozer]
log_level = 2
warn_on_root = 1
