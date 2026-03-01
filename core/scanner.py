"""
Network Device Scanner
Scans all devices connected to the local network using ARP
"""

import threading
import time
import socket
import subprocess
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


OUI_MAP = {
    # VMware / Virtualization
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    # Apple
    "00:1b:63": "Apple", "ac:de:48": "Apple", "f0:18:98": "Apple",
    "3c:22:fb": "Apple", "a4:c3:f0": "Apple", "f8:ff:c2": "Apple",
    "00:17:f2": "Apple", "00:1e:c2": "Apple", "00:23:12": "Apple",
    "00:25:00": "Apple", "00:26:b9": "Apple", "28:cf:e9": "Apple",
    "3c:07:54": "Apple", "40:6c:8f": "Apple", "44:fb:42": "Apple",
    "60:f8:1d": "Apple", "70:56:81": "Apple", "78:4f:43": "Apple",
    "7c:6d:62": "Apple", "88:63:df": "Apple", "90:72:40": "Apple",
    "a8:86:dd": "Apple", "b8:8d:12": "Apple", "c8:2a:14": "Apple",
    "d0:23:db": "Apple", "e0:f8:47": "Apple", "f4:f1:5a": "Apple",
    # Samsung
    "00:12:47": "Samsung", "00:15:b9": "Samsung", "00:17:c9": "Samsung",
    "00:1a:8a": "Samsung", "00:1d:25": "Samsung", "00:1e:7d": "Samsung",
    "00:21:19": "Samsung", "00:23:39": "Samsung", "00:26:37": "Samsung",
    "08:08:c2": "Samsung", "08:d4:2b": "Samsung", "10:1d:c0": "Samsung",
    "14:49:e0": "Samsung", "18:3a:2d": "Samsung", "1c:62:b8": "Samsung",
    "20:13:e0": "Samsung", "24:4b:03": "Samsung", "28:ba:b5": "Samsung",
    "2c:ae:2b": "Samsung", "30:19:66": "Samsung", "34:23:ba": "Samsung",
    "38:01:97": "Samsung", "3c:8b:fe": "Samsung", "40:0e:85": "Samsung",
    "44:4e:1a": "Samsung", "48:44:f7": "Samsung", "4c:bc:a5": "Samsung",
    "50:01:bb": "Samsung", "54:88:0e": "Samsung", "58:ef:68": "Samsung",
    "5c:49:79": "Samsung", "60:6b:bd": "Samsung", "64:b3:10": "Samsung",
    "68:eb:ae": "Samsung", "6c:2f:2c": "Samsung", "70:f9:27": "Samsung",
    "74:45:8a": "Samsung", "78:1f:db": "Samsung", "7c:0b:c6": "Samsung",
    "80:65:6d": "Samsung", "84:25:db": "Samsung", "88:32:9b": "Samsung",
    "8c:77:12": "Samsung", "90:18:7c": "Samsung", "94:35:0a": "Samsung",
    "98:52:b1": "Samsung", "9c:02:98": "Samsung", "a0:07:98": "Samsung",
    "a4:eb:d3": "Samsung", "a8:06:00": "Samsung", "ac:5f:3e": "Samsung",
    "b0:72:bf": "Samsung", "b4:07:f9": "Samsung", "b8:5e:7b": "Samsung",
    "bc:20:a4": "Samsung", "c0:bd:d1": "Samsung", "c4:42:02": "Samsung",
    "c8:ba:94": "Samsung", "cc:07:ab": "Samsung", "d0:22:be": "Samsung",
    "d4:88:90": "Samsung", "d8:57:ef": "Samsung", "dc:71:96": "Samsung",
    "e0:99:71": "Samsung", "e4:40:e2": "Samsung", "e8:50:8b": "Samsung",
    "ec:1f:72": "Samsung", "f0:25:b7": "Samsung", "f4:42:8f": "Samsung",
    "f8:04:2e": "Samsung", "fc:a1:3e": "Samsung",
    # Xiaomi
    "00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "08:7a:4c": "Xiaomi",
    "0c:1d:af": "Xiaomi", "10:2a:b3": "Xiaomi", "14:f6:5a": "Xiaomi",
    "18:59:36": "Xiaomi", "1c:5f:2b": "Xiaomi", "20:82:c0": "Xiaomi",
    "28:6c:07": "Xiaomi", "2c:4d:54": "Xiaomi", "34:80:b3": "Xiaomi",
    "38:a4:ed": "Xiaomi", "3c:bd:d8": "Xiaomi", "40:31:3c": "Xiaomi",
    "44:a1:91": "Xiaomi", "50:8f:4c": "Xiaomi", "58:44:98": "Xiaomi",
    "5c:e8:eb": "Xiaomi", "60:ab:67": "Xiaomi", "64:09:80": "Xiaomi",
    "68:df:dd": "Xiaomi", "6c:40:08": "Xiaomi", "74:23:44": "Xiaomi",
    "78:11:dc": "Xiaomi", "7c:1d:d9": "Xiaomi", "8c:be:be": "Xiaomi",
    "98:fa:e3": "Xiaomi", "9c:99:a0": "Xiaomi", "a0:86:c6": "Xiaomi",
    "ac:c1:ee": "Xiaomi", "b0:e2:35": "Xiaomi", "c4:0b:cb": "Xiaomi",
    "d4:97:0b": "Xiaomi", "f4:8b:32": "Xiaomi", "f8:a4:5f": "Xiaomi",
    "fc:64:ba": "Xiaomi",
    # Huawei
    "00:18:82": "Huawei", "00:1e:10": "Huawei", "00:25:9e": "Huawei",
    "04:02:1f": "Huawei", "04:75:03": "Huawei", "04:bd:70": "Huawei",
    "04:c0:6f": "Huawei", "04:f9:38": "Huawei", "08:19:a6": "Huawei",
    "0c:37:dc": "Huawei", "10:1b:54": "Huawei", "10:47:80": "Huawei",
    "14:9d:09": "Huawei", "18:c5:8a": "Huawei", "1c:8e:5c": "Huawei",
    "20:08:ed": "Huawei", "20:f3:a3": "Huawei", "24:09:95": "Huawei",
    "28:31:52": "Huawei", "2c:ab:00": "Huawei", "30:d1:7e": "Huawei",
    "34:6b:d3": "Huawei", "38:37:8b": "Huawei", "3c:47:11": "Huawei",
    "40:4d:8e": "Huawei", "44:6a:2e": "Huawei", "48:00:31": "Huawei",
    "4c:1f:cc": "Huawei", "50:9f:27": "Huawei", "54:89:98": "Huawei",
    "58:2a:f7": "Huawei", "5c:c3:07": "Huawei", "60:de:44": "Huawei",
    "64:16:f0": "Huawei", "68:a0:f6": "Huawei", "6c:8d:c1": "Huawei",
    "70:72:3c": "Huawei", "74:a0:63": "Huawei", "78:1d:ba": "Huawei",
    "7c:a2:3e": "Huawei", "80:fb:06": "Huawei", "84:a8:e4": "Huawei",
    "88:e3:ab": "Huawei", "8c:34:fd": "Huawei", "90:67:1c": "Huawei",
    "94:77:2b": "Huawei", "98:e7:f4": "Huawei", "9c:28:ef": "Huawei",
    "a0:08:6f": "Huawei", "a4:50:46": "Huawei", "a8:ca:7b": "Huawei",
    "ac:e2:15": "Huawei", "b0:e5:ed": "Huawei", "b4:15:13": "Huawei",
    "b8:08:d7": "Huawei", "bc:25:e0": "Huawei", "c0:70:09": "Huawei",
    "c4:07:2f": "Huawei", "c8:51:95": "Huawei", "cc:96:a0": "Huawei",
    "d0:7a:b5": "Huawei", "d4:6e:5c": "Huawei", "d8:c7:71": "Huawei",
    "dc:d2:fc": "Huawei", "e0:19:54": "Huawei", "e4:68:a3": "Huawei",
    "e8:cd:2d": "Huawei", "ec:23:3d": "Huawei", "f0:79:59": "Huawei",
    "f4:9f:f3": "Huawei", "f8:3d:ff": "Huawei", "fc:48:ef": "Huawei",
    # TP-Link
    "00:1d:0f": "TP-Link", "14:cc:20": "TP-Link", "18:a6:f7": "TP-Link",
    "1c:3b:f3": "TP-Link", "20:dc:e6": "TP-Link", "24:69:68": "TP-Link",
    "28:2c:b2": "TP-Link", "2c:d0:5a": "TP-Link", "30:b5:c2": "TP-Link",
    "34:60:f9": "TP-Link", "38:94:ed": "TP-Link", "3c:84:6a": "TP-Link",
    "40:16:9f": "TP-Link", "44:94:fc": "TP-Link", "48:8f:5a": "TP-Link",
    "4c:e1:73": "TP-Link", "50:c7:bf": "TP-Link", "54:af:97": "TP-Link",
    "58:d5:6e": "TP-Link", "5c:89:9a": "TP-Link", "60:32:b1": "TP-Link",
    "64:70:02": "TP-Link", "68:ff:7b": "TP-Link", "6c:5a:b0": "TP-Link",
    "70:4f:57": "TP-Link", "74:da:38": "TP-Link", "78:8a:20": "TP-Link",
    "7c:8b:ca": "TP-Link", "80:35:c1": "TP-Link", "84:16:f9": "TP-Link",
    "88:25:93": "TP-Link", "8c:21:0a": "TP-Link", "90:f6:52": "TP-Link",
    "94:d9:b3": "TP-Link", "98:da:c4": "TP-Link", "9c:a6:15": "TP-Link",
    "a0:f3:c1": "TP-Link", "a4:2b:b0": "TP-Link", "a8:57:4e": "TP-Link",
    "ac:84:c6": "TP-Link", "b0:48:7a": "TP-Link", "b4:b0:24": "TP-Link",
    "b8:a3:77": "TP-Link", "bc:46:99": "TP-Link", "c0:4a:00": "TP-Link",
    "c4:e9:84": "TP-Link", "c8:d3:a3": "TP-Link", "cc:32:e5": "TP-Link",
    "d0:37:45": "TP-Link", "d4:6e:0e": "TP-Link", "d8:0d:17": "TP-Link",
    "dc:fe:18": "TP-Link", "e0:05:c5": "TP-Link", "e4:c3:2a": "TP-Link",
    "e8:de:27": "TP-Link", "ec:08:6b": "TP-Link", "f0:a7:31": "TP-Link",
    "f4:ec:38": "TP-Link", "f8:1a:67": "TP-Link", "fc:ec:da": "TP-Link",
    # ASUS
    "00:0c:6e": "ASUS", "00:11:2f": "ASUS", "00:13:d4": "ASUS",
    "00:15:f2": "ASUS", "00:17:31": "ASUS", "00:1a:92": "ASUS",
    "00:1d:60": "ASUS", "00:1e:8c": "ASUS", "00:1f:c6": "ASUS",
    "00:22:15": "ASUS", "00:23:54": "ASUS", "00:24:8c": "ASUS",
    "00:26:18": "ASUS", "04:92:26": "ASUS", "08:60:6e": "ASUS",
    "0c:9d:92": "ASUS", "10:7b:44": "ASUS", "14:da:e9": "ASUS",
    "18:31:bf": "ASUS", "1c:87:2c": "ASUS", "20:cf:30": "ASUS",
    "24:4b:fe": "ASUS", "2c:56:dc": "ASUS", "30:5a:3a": "ASUS",
    "34:97:f6": "ASUS", "38:d5:47": "ASUS", "3c:97:0e": "ASUS",
    "40:b0:76": "ASUS", "44:8a:5b": "ASUS", "48:5b:39": "ASUS",
    "4c:ed:fb": "ASUS", "50:46:5d": "ASUS", "54:04:a6": "ASUS",
    "58:11:22": "ASUS", "5c:ff:35": "ASUS", "60:45:cb": "ASUS",
    "64:d1:54": "ASUS", "6c:62:6d": "ASUS", "70:8b:cd": "ASUS",
    "74:d0:2b": "ASUS", "78:24:af": "ASUS", "7c:10:c9": "ASUS",
    "80:1f:02": "ASUS", "84:a9:c4": "ASUS", "88:d7:f6": "ASUS",
    "8c:89:a5": "ASUS", "90:e6:ba": "ASUS", "94:de:80": "ASUS",
    "98:3b:8f": "ASUS", "9c:5c:8e": "ASUS", "a0:36:9f": "ASUS",
    "a4:5e:60": "ASUS", "a8:5e:45": "ASUS", "ac:22:0b": "ASUS",
    "b0:6e:bf": "ASUS", "b4:2e:99": "ASUS", "b8:ae:ed": "ASUS",
    "bc:ae:c5": "ASUS", "c8:60:00": "ASUS", "cc:28:aa": "ASUS",
    "d0:17:c2": "ASUS", "d4:5d:64": "ASUS", "d8:50:e6": "ASUS",
    "dc:4a:3e": "ASUS", "e0:3f:49": "ASUS", "e4:70:b8": "ASUS",
    "e8:9a:8f": "ASUS", "ec:4c:4d": "ASUS", "f0:2f:74": "ASUS",
    "f4:6d:04": "ASUS", "f8:32:e4": "ASUS", "fc:34:97": "ASUS",
    # Intel (WiFi adapters)
    "00:02:b3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:07:e9": "Intel", "00:0c:f1": "Intel", "00:0e:0c": "Intel",
    "00:0e:35": "Intel", "00:11:11": "Intel", "00:12:f0": "Intel",
    "00:13:02": "Intel", "00:13:20": "Intel", "00:13:ce": "Intel",
    "00:13:e8": "Intel", "00:15:00": "Intel", "00:16:76": "Intel",
    "00:16:ea": "Intel", "00:16:eb": "Intel", "00:18:de": "Intel",
    "00:19:d1": "Intel", "00:19:d2": "Intel", "00:1b:21": "Intel",
    "00:1c:bf": "Intel", "00:1d:e0": "Intel", "00:1e:64": "Intel",
    "00:1e:65": "Intel", "00:1f:3b": "Intel", "00:1f:3c": "Intel",
    "00:21:6a": "Intel", "00:22:fa": "Intel", "00:23:14": "Intel",
    "00:24:d6": "Intel", "00:24:d7": "Intel", "00:27:10": "Intel",
    "8c:8d:28": "Intel", "a4:c3:f0": "Intel",
    # Realtek
    "00:01:6c": "Realtek", "00:e0:4c": "Realtek", "52:54:00": "Realtek",
    # Cisco
    "00:00:0c": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
    "00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
    "00:01:97": "Cisco", "00:01:c7": "Cisco", "00:01:c9": "Cisco",
    "00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:3d": "Cisco",
    "00:02:4a": "Cisco", "00:02:4b": "Cisco", "00:02:7d": "Cisco",
    "00:02:7e": "Cisco", "00:02:b9": "Cisco", "00:02:ba": "Cisco",
    "00:03:31": "Cisco", "00:03:32": "Cisco", "00:03:6b": "Cisco",
    "00:03:6c": "Cisco", "00:03:9f": "Cisco", "00:03:a0": "Cisco",
    "00:03:e3": "Cisco", "00:03:e4": "Cisco", "00:03:fd": "Cisco",
    "00:03:fe": "Cisco", "00:04:27": "Cisco", "00:04:28": "Cisco",
    "00:04:4d": "Cisco", "00:04:4e": "Cisco", "00:04:6d": "Cisco",
    "00:04:6e": "Cisco", "00:04:9a": "Cisco", "00:04:9b": "Cisco",
    "00:04:c0": "Cisco", "00:04:c1": "Cisco", "00:04:dd": "Cisco",
    "00:04:de": "Cisco", "00:05:00": "Cisco", "00:05:01": "Cisco",
    "00:05:31": "Cisco", "00:05:32": "Cisco", "00:05:5e": "Cisco",
    "00:05:5f": "Cisco", "00:05:73": "Cisco", "00:05:74": "Cisco",
    "00:05:9a": "Cisco", "00:05:9b": "Cisco", "00:05:dc": "Cisco",
    "00:05:dd": "Cisco", "00:06:28": "Cisco", "00:06:52": "Cisco",
    "00:06:53": "Cisco", "00:06:7c": "Cisco", "00:06:7d": "Cisco",
    "00:06:c1": "Cisco", "00:06:d6": "Cisco", "00:06:d7": "Cisco",
    "00:06:f6": "Cisco", "00:07:0d": "Cisco", "00:07:0e": "Cisco",
    "00:07:4f": "Cisco", "00:07:50": "Cisco", "00:07:7d": "Cisco",
    "00:07:7e": "Cisco", "00:07:84": "Cisco", "00:07:85": "Cisco",
    "00:07:b3": "Cisco", "00:07:b4": "Cisco", "00:07:eb": "Cisco",
    "00:07:ec": "Cisco", "00:08:20": "Cisco", "00:08:21": "Cisco",
    "00:08:30": "Cisco", "00:08:31": "Cisco", "00:08:7c": "Cisco",
    "00:08:7d": "Cisco", "00:08:a3": "Cisco", "00:08:a4": "Cisco",
    "00:08:e2": "Cisco", "00:08:e3": "Cisco", "00:09:11": "Cisco",
    "00:09:12": "Cisco", "00:09:43": "Cisco", "00:09:44": "Cisco",
    "00:09:7b": "Cisco", "00:09:7c": "Cisco", "00:09:b6": "Cisco",
    "00:09:b7": "Cisco", "00:09:e8": "Cisco", "00:09:e9": "Cisco",
    "00:0a:41": "Cisco", "00:0a:42": "Cisco", "00:0a:8a": "Cisco",
    "00:0a:8b": "Cisco", "00:0a:b8": "Cisco", "00:0a:b9": "Cisco",
    "00:0a:f3": "Cisco", "00:0a:f4": "Cisco", "00:0b:45": "Cisco",
    "00:0b:46": "Cisco", "00:0b:5f": "Cisco", "00:0b:60": "Cisco",
    "00:0b:85": "Cisco", "00:0b:be": "Cisco", "00:0b:bf": "Cisco",
    "00:0b:fc": "Cisco", "00:0b:fd": "Cisco", "00:0c:30": "Cisco",
    "00:0c:31": "Cisco", "00:0c:85": "Cisco", "00:0c:86": "Cisco",
    "00:0c:ce": "Cisco", "00:0c:cf": "Cisco", "00:0c:f8": "Cisco",
    "00:0c:f9": "Cisco", "00:0d:28": "Cisco", "00:0d:29": "Cisco",
    "00:0d:65": "Cisco", "00:0d:66": "Cisco", "00:0d:bc": "Cisco",
    "00:0d:bd": "Cisco", "00:0d:ec": "Cisco", "00:0d:ed": "Cisco",
    "00:0e:08": "Cisco", "00:0e:38": "Cisco", "00:0e:39": "Cisco",
    "00:0e:83": "Cisco", "00:0e:84": "Cisco", "00:0e:d7": "Cisco",
    "00:0e:d8": "Cisco", "00:0f:23": "Cisco", "00:0f:24": "Cisco",
    "00:0f:34": "Cisco", "00:0f:35": "Cisco", "00:0f:8f": "Cisco",
    "00:0f:90": "Cisco", "00:0f:f7": "Cisco", "00:0f:f8": "Cisco",
    "00:10:07": "Cisco", "00:10:0d": "Cisco", "00:10:11": "Cisco",
    "00:10:14": "Cisco", "00:10:1f": "Cisco", "00:10:29": "Cisco",
    "00:10:2f": "Cisco", "00:10:54": "Cisco", "00:10:79": "Cisco",
    "00:10:7b": "Cisco", "00:10:a6": "Cisco", "00:10:f6": "Cisco",
    "00:11:20": "Cisco", "00:11:21": "Cisco", "00:11:5c": "Cisco",
    "00:11:5d": "Cisco", "00:11:92": "Cisco", "00:11:93": "Cisco",
    "00:11:bb": "Cisco", "00:11:bc": "Cisco", "00:12:00": "Cisco",
    "00:12:01": "Cisco", "00:12:43": "Cisco", "00:12:44": "Cisco",
    "00:12:7f": "Cisco", "00:12:80": "Cisco", "00:12:d9": "Cisco",
    "00:12:da": "Cisco", "00:13:1a": "Cisco", "00:13:1b": "Cisco",
    "00:13:5f": "Cisco", "00:13:60": "Cisco", "00:13:7f": "Cisco",
    "00:13:80": "Cisco", "00:13:c3": "Cisco", "00:13:c4": "Cisco",
    "00:14:1b": "Cisco", "00:14:1c": "Cisco", "00:14:69": "Cisco",
    "00:14:6a": "Cisco", "00:14:a9": "Cisco", "00:14:aa": "Cisco",
    "00:14:bf": "Cisco", "00:14:f1": "Cisco", "00:14:f2": "Cisco",
    "00:15:2b": "Cisco", "00:15:2c": "Cisco", "00:15:62": "Cisco",
    "00:15:63": "Cisco", "00:15:c6": "Cisco", "00:15:c7": "Cisco",
    "00:15:f9": "Cisco", "00:15:fa": "Cisco", "00:16:46": "Cisco",
    "00:16:47": "Cisco", "00:16:9c": "Cisco", "00:16:9d": "Cisco",
    "00:16:c7": "Cisco", "00:16:c8": "Cisco", "00:17:0e": "Cisco",
    "00:17:0f": "Cisco", "00:17:59": "Cisco", "00:17:5a": "Cisco",
    "00:17:94": "Cisco", "00:17:95": "Cisco", "00:17:df": "Cisco",
    "00:17:e0": "Cisco", "00:18:18": "Cisco", "00:18:19": "Cisco",
    "00:18:39": "Cisco", "00:18:3a": "Cisco", "00:18:68": "Cisco",
    "00:18:69": "Cisco", "00:18:b9": "Cisco", "00:18:ba": "Cisco",
    "00:19:06": "Cisco", "00:19:07": "Cisco", "00:19:2f": "Cisco",
    "00:19:30": "Cisco", "00:19:55": "Cisco", "00:19:56": "Cisco",
    "00:19:a9": "Cisco", "00:19:aa": "Cisco", "00:19:e7": "Cisco",
    "00:19:e8": "Cisco", "00:1a:2b": "Cisco", "00:1a:2c": "Cisco",
    "00:1a:6c": "Cisco", "00:1a:6d": "Cisco", "00:1a:a1": "Cisco",
    "00:1a:a2": "Cisco", "00:1a:e2": "Cisco", "00:1a:e3": "Cisco",
    "00:1b:0c": "Cisco", "00:1b:0d": "Cisco", "00:1b:2a": "Cisco",
    "00:1b:2b": "Cisco", "00:1b:53": "Cisco", "00:1b:54": "Cisco",
    "00:1b:8f": "Cisco", "00:1b:90": "Cisco", "00:1b:d4": "Cisco",
    "00:1b:d5": "Cisco", "00:1c:0e": "Cisco", "00:1c:0f": "Cisco",
    "00:1c:57": "Cisco", "00:1c:58": "Cisco", "00:1c:b0": "Cisco",
    "00:1c:b1": "Cisco", "00:1c:f6": "Cisco", "00:1c:f9": "Cisco",
    "00:1d:45": "Cisco", "00:1d:46": "Cisco", "00:1d:70": "Cisco",
    "00:1d:71": "Cisco", "00:1d:a1": "Cisco", "00:1d:a2": "Cisco",
    "00:1d:e5": "Cisco", "00:1d:e6": "Cisco", "00:1e:13": "Cisco",
    "00:1e:14": "Cisco", "00:1e:49": "Cisco", "00:1e:4a": "Cisco",
    "00:1e:6b": "Cisco", "00:1e:6c": "Cisco", "00:1e:7a": "Cisco",
    "00:1e:7b": "Cisco", "00:1e:bd": "Cisco", "00:1e:be": "Cisco",
    "00:1e:e5": "Cisco", "00:1e:e6": "Cisco", "00:1e:f6": "Cisco",
    "00:1e:f7": "Cisco", "00:1f:26": "Cisco", "00:1f:27": "Cisco",
    "00:1f:6c": "Cisco", "00:1f:6d": "Cisco", "00:1f:9e": "Cisco",
    "00:1f:9f": "Cisco", "00:1f:ca": "Cisco", "00:1f:cb": "Cisco",
    "00:21:1b": "Cisco", "00:21:1c": "Cisco", "00:21:55": "Cisco",
    "00:21:56": "Cisco", "00:21:a0": "Cisco", "00:21:a1": "Cisco",
    "00:21:be": "Cisco", "00:21:bf": "Cisco", "00:22:0c": "Cisco",
    "00:22:0d": "Cisco", "00:22:55": "Cisco", "00:22:56": "Cisco",
    "00:22:90": "Cisco", "00:22:91": "Cisco", "00:22:bd": "Cisco",
    "00:22:be": "Cisco", "00:23:04": "Cisco", "00:23:05": "Cisco",
    "00:23:33": "Cisco", "00:23:34": "Cisco", "00:23:5e": "Cisco",
    "00:23:5f": "Cisco", "00:23:ac": "Cisco", "00:23:ad": "Cisco",
    "00:23:be": "Cisco", "00:23:bf": "Cisco", "00:23:eb": "Cisco",
    "00:23:ec": "Cisco", "00:24:13": "Cisco", "00:24:14": "Cisco",
    "00:24:50": "Cisco", "00:24:51": "Cisco", "00:24:97": "Cisco",
    "00:24:98": "Cisco", "00:24:c3": "Cisco", "00:24:c4": "Cisco",
    "00:24:f7": "Cisco", "00:24:f9": "Cisco", "00:25:45": "Cisco",
    "00:25:46": "Cisco", "00:25:83": "Cisco", "00:25:84": "Cisco",
    "00:25:b4": "Cisco", "00:25:b5": "Cisco", "00:26:0a": "Cisco",
    "00:26:0b": "Cisco", "00:26:51": "Cisco", "00:26:52": "Cisco",
    "00:26:98": "Cisco", "00:26:99": "Cisco", "00:26:ca": "Cisco",
    "00:26:cb": "Cisco",
    # D-Link
    "00:05:5d": "D-Link", "00:0d:88": "D-Link", "00:0f:3d": "D-Link",
    "00:11:95": "D-Link", "00:13:46": "D-Link", "00:15:e9": "D-Link",
    "00:17:9a": "D-Link", "00:19:5b": "D-Link", "00:1b:11": "D-Link",
    "00:1c:f0": "D-Link", "00:1e:58": "D-Link", "00:21:91": "D-Link",
    "00:22:b0": "D-Link", "00:24:01": "D-Link", "00:26:5a": "D-Link",
    "1c:7e:e5": "D-Link", "1c:af:f7": "D-Link", "28:10:7b": "D-Link",
    "34:08:04": "D-Link", "5c:d9:98": "D-Link", "78:54:2e": "D-Link",
    "84:c9:b2": "D-Link", "90:94:e4": "D-Link", "b8:a3:86": "D-Link",
    "c8:be:19": "D-Link", "cc:b2:55": "D-Link", "f0:7d:68": "D-Link",
    "f0:b4:29": "D-Link",
    # Netgear
    "00:09:5b": "Netgear", "00:0f:b5": "Netgear", "00:14:6c": "Netgear",
    "00:18:4d": "Netgear", "00:1b:2f": "Netgear", "00:1e:2a": "Netgear",
    "00:1f:33": "Netgear", "00:22:3f": "Netgear", "00:24:b2": "Netgear",
    "00:26:f2": "Netgear", "20:4e:7f": "Netgear", "28:c6:8e": "Netgear",
    "2c:b0:5d": "Netgear", "30:46:9a": "Netgear", "44:94:fc": "Netgear",
    "4c:60:de": "Netgear", "6c:b0:ce": "Netgear", "84:1b:5e": "Netgear",
    "a0:21:b7": "Netgear", "a4:2b:8c": "Netgear", "c0:3f:0e": "Netgear",
    "c4:04:15": "Netgear", "e0:46:9a": "Netgear", "e4:f4:c6": "Netgear",
    # Oppo / OnePlus
    "00:1a:ef": "OPPO", "04:d6:aa": "OPPO", "08:f4:ab": "OPPO",
    "0c:1d:af": "OPPO", "10:68:3f": "OPPO", "18:26:49": "OPPO",
    "1c:77:f6": "OPPO", "20:47:da": "OPPO", "28:ba:b5": "OPPO",
    "2c:5b:b8": "OPPO", "34:14:5f": "OPPO", "38:bc:01": "OPPO",
    "3c:cb:7c": "OPPO", "40:4e:36": "OPPO", "44:74:6c": "OPPO",
    "48:db:50": "OPPO", "4c:03:4f": "OPPO", "50:2c:c8": "OPPO",
    "54:35:30": "OPPO", "58:a2:b5": "OPPO", "5c:e8:eb": "OPPO",
    "60:d9:a0": "OPPO", "64:a2:f9": "OPPO", "68:3e:34": "OPPO",
    "6c:5c:14": "OPPO", "70:3a:cb": "OPPO", "74:51:ba": "OPPO",
    "78:d7:5f": "OPPO", "7c:9e:bd": "OPPO", "80:4e:70": "OPPO",
    "84:db:ac": "OPPO", "88:c9:d0": "OPPO", "8c:0e:e3": "OPPO",
    "90:b6:86": "OPPO", "94:65:2d": "OPPO", "98:28:a6": "OPPO",
    "9c:b6:d0": "OPPO", "a0:d3:7a": "OPPO", "a4:77:33": "OPPO",
    "a8:9f:ec": "OPPO", "ac:37:43": "OPPO", "b0:e5:ed": "OPPO",
    "b4:a5:ef": "OPPO", "b8:bc:1b": "OPPO", "bc:f1:71": "OPPO",
    "c0:ee:fb": "OPPO", "c4:86:e9": "OPPO", "c8:14:79": "OPPO",
    "cc:a3:00": "OPPO", "d0:76:8f": "OPPO", "d4:50:3f": "OPPO",
    "d8:f8:83": "OPPO", "dc:85:de": "OPPO", "e0:b6:55": "OPPO",
    "e4:a7:c5": "OPPO", "e8:bb:a8": "OPPO", "ec:df:3a": "OPPO",
    "f0:43:47": "OPPO", "f4:63:1f": "OPPO", "f8:a9:d0": "OPPO",
    "fc:19:d0": "OPPO",
    # Vivo
    "00:e0:4c": "Vivo", "04:d9:f5": "Vivo", "08:9e:01": "Vivo",
    "0c:96:e6": "Vivo", "10:3b:59": "Vivo", "14:75:90": "Vivo",
    "18:65:90": "Vivo", "1c:99:4c": "Vivo", "20:f4:1b": "Vivo",
    "24:62:ab": "Vivo", "28:6d:cd": "Vivo", "2c:f0:5d": "Vivo",
    "30:74:96": "Vivo", "34:4d:f7": "Vivo", "38:68:a4": "Vivo",
    "3c:f8:62": "Vivo", "40:b8:9a": "Vivo", "44:d8:84": "Vivo",
    "48:02:2a": "Vivo", "4c:49:e3": "Vivo", "50:2f:9b": "Vivo",
    "54:a0:50": "Vivo", "58:63:56": "Vivo", "5c:e0:c5": "Vivo",
    "60:83:e7": "Vivo", "64:cc:2e": "Vivo", "68:3a:1e": "Vivo",
    "6c:b7:f4": "Vivo", "70:47:e9": "Vivo", "74:e5:43": "Vivo",
    "78:a3:e4": "Vivo", "7c:76:35": "Vivo", "80:91:33": "Vivo",
    "84:cf:bf": "Vivo", "88:44:77": "Vivo", "8c:79:f0": "Vivo",
    "90:c1:15": "Vivo", "94:87:e0": "Vivo", "98:01:a7": "Vivo",
    "9c:d2:1e": "Vivo", "a0:af:bd": "Vivo", "a4:c4:94": "Vivo",
    "a8:db:03": "Vivo", "ac:67:b2": "Vivo", "b0:d5:9d": "Vivo",
    "b4:86:55": "Vivo", "b8:f8:83": "Vivo", "bc:54:51": "Vivo",
    "c0:25:a2": "Vivo", "c4:ac:59": "Vivo", "c8:f7:50": "Vivo",
    "cc:2d:e0": "Vivo", "d0:c6:37": "Vivo", "d4:f5:27": "Vivo",
    "d8:b0:4c": "Vivo", "dc:44:27": "Vivo", "e0:d4:e8": "Vivo",
    "e4:02:9b": "Vivo", "e8:d8:d1": "Vivo", "ec:9b:f3": "Vivo",
    "f0:d5:bf": "Vivo", "f4:60:e2": "Vivo", "f8:59:71": "Vivo",
    "fc:3f:7c": "Vivo",
    # Google / Android
    "00:1a:11": "Google", "08:9e:08": "Google", "1c:f2:9a": "Google",
    "20:df:b9": "Google", "3c:5a:b4": "Google", "48:d6:d5": "Google",
    "54:60:09": "Google", "6c:ad:f8": "Google", "70:3a:51": "Google",
    "94:eb:2c": "Google", "a4:77:33": "Google", "f4:f5:d8": "Google",
    "f8:8f:ca": "Google",
    # Amazon / Echo
    "00:fc:8b": "Amazon", "0c:47:c9": "Amazon", "10:ae:60": "Amazon",
    "18:74:2e": "Amazon", "1c:12:b0": "Amazon", "28:ef:01": "Amazon",
    "34:d2:70": "Amazon", "40:b4:cd": "Amazon", "44:65:0d": "Amazon",
    "4c:ef:c0": "Amazon", "50:f5:da": "Amazon", "54:4e:90": "Amazon",
    "58:cb:52": "Amazon", "5c:a6:e6": "Amazon", "60:f1:89": "Amazon",
    "68:37:e9": "Amazon", "6c:56:97": "Amazon", "74:c2:46": "Amazon",
    "78:e1:03": "Amazon", "7c:bb:8a": "Amazon", "84:d6:d0": "Amazon",
    "88:71:e5": "Amazon", "8c:85:90": "Amazon", "90:59:af": "Amazon",
    "a0:02:dc": "Amazon", "a4:08:01": "Amazon", "a8:bb:cf": "Amazon",
    "ac:63:be": "Amazon", "b0:fc:0d": "Amazon", "b4:7c:9c": "Amazon",
    "b8:27:eb": "Amazon", "bc:54:36": "Amazon", "c0:ee:fb": "Amazon",
    "c4:a3:66": "Amazon", "c8:d0:83": "Amazon", "cc:9e:a2": "Amazon",
    "d0:03:4b": "Amazon", "d4:f5:47": "Amazon", "d8:96:95": "Amazon",
    "dc:a9:04": "Amazon", "e0:28:6d": "Amazon", "e4:ce:8f": "Amazon",
    "e8:bb:a8": "Amazon", "ec:1b:bd": "Amazon", "f0:27:2d": "Amazon",
    "f4:39:09": "Amazon", "f8:04:2e": "Amazon", "fc:65:de": "Amazon",
    # Lenovo
    "00:1e:4f": "Lenovo", "00:21:cc": "Lenovo", "00:23:ae": "Lenovo",
    "00:24:7e": "Lenovo", "00:26:b9": "Lenovo", "04:5d:4b": "Lenovo",
    "08:3a:88": "Lenovo", "0c:8b:fd": "Lenovo", "10:02:b5": "Lenovo",
    "14:1a:a3": "Lenovo", "18:5e:0f": "Lenovo", "1c:1b:0d": "Lenovo",
    "20:89:84": "Lenovo", "24:4b:fe": "Lenovo", "28:d2:44": "Lenovo",
    "2c:44:fd": "Lenovo", "30:10:b3": "Lenovo", "34:73:5a": "Lenovo",
    "38:b1:db": "Lenovo", "3c:97:0e": "Lenovo", "40:2c:f4": "Lenovo",
    "44:85:00": "Lenovo", "48:51:b7": "Lenovo", "4c:79:6e": "Lenovo",
    "50:7b:9d": "Lenovo", "54:ee:75": "Lenovo", "58:8f:c3": "Lenovo",
    "5c:f3:70": "Lenovo", "60:02:b4": "Lenovo", "64:5a:04": "Lenovo",
    "68:5d:43": "Lenovo", "6c:88:14": "Lenovo", "70:5a:0f": "Lenovo",
    "74:df:bf": "Lenovo", "78:45:c4": "Lenovo", "7c:7a:91": "Lenovo",
    "80:56:f2": "Lenovo", "84:7b:eb": "Lenovo", "88:70:8c": "Lenovo",
    "8c:8d:28": "Lenovo", "90:7f:61": "Lenovo", "94:65:9c": "Lenovo",
    "98:fa:9b": "Lenovo", "9c:b6:54": "Lenovo", "a0:1d:48": "Lenovo",
    "a4:4e:31": "Lenovo", "a8:6b:ad": "Lenovo", "ac:b5:7d": "Lenovo",
    "b0:35:9f": "Lenovo", "b4:6b:fc": "Lenovo", "b8:63:4d": "Lenovo",
    "bc:5f:f4": "Lenovo", "c0:b8:83": "Lenovo", "c4:65:16": "Lenovo",
    "c8:5b:76": "Lenovo", "cc:f9:54": "Lenovo", "d0:53:49": "Lenovo",
    "d4:81:d7": "Lenovo", "d8:bb:c1": "Lenovo", "dc:53:60": "Lenovo",
    "e0:94:67": "Lenovo", "e4:54:e8": "Lenovo", "e8:6a:64": "Lenovo",
    "ec:f4:bb": "Lenovo", "f0:de:f1": "Lenovo", "f4:8e:38": "Lenovo",
    "f8:16:54": "Lenovo", "fc:f8:ae": "Lenovo",
    # Dell
    "00:06:5b": "Dell", "00:08:74": "Dell", "00:0b:db": "Dell",
    "00:0d:56": "Dell", "00:0f:1f": "Dell", "00:11:43": "Dell",
    "00:12:3f": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
    "00:15:c5": "Dell", "00:16:f0": "Dell", "00:18:8b": "Dell",
    "00:19:b9": "Dell", "00:1a:4b": "Dell", "00:1c:23": "Dell",
    "00:1d:09": "Dell", "00:1e:4f": "Dell", "00:21:70": "Dell",
    "00:22:19": "Dell", "00:23:ae": "Dell", "00:24:e8": "Dell",
    "00:25:64": "Dell", "00:26:b9": "Dell", "18:03:73": "Dell",
    "18:66:da": "Dell", "18:a9:9b": "Dell", "1c:40:24": "Dell",
    "20:47:47": "Dell", "24:b6:fd": "Dell", "28:f1:0e": "Dell",
    "2c:76:8a": "Dell", "34:17:eb": "Dell", "38:ea:a7": "Dell",
    "3c:2c:30": "Dell", "40:a8:f0": "Dell", "44:a8:42": "Dell",
    "48:4d:7e": "Dell", "4c:d9:8f": "Dell", "50:9a:4c": "Dell",
    "54:9f:35": "Dell", "58:8a:5a": "Dell", "5c:26:0a": "Dell",
    "60:36:dd": "Dell", "64:00:6a": "Dell", "68:05:ca": "Dell",
    "6c:2b:59": "Dell", "70:10:6f": "Dell", "74:86:7a": "Dell",
    "78:2b:cb": "Dell", "7c:d1:c3": "Dell", "80:18:44": "Dell",
    "84:7b:57": "Dell", "88:51:fb": "Dell", "8c:ec:4b": "Dell",
    "90:b1:1c": "Dell", "94:18:82": "Dell", "98:90:96": "Dell",
    "9c:eb:e8": "Dell", "a0:36:9f": "Dell", "a4:1f:72": "Dell",
    "a8:9f:ba": "Dell", "ac:16:2d": "Dell", "b0:83:fe": "Dell",
    "b4:45:06": "Dell", "b8:ca:3a": "Dell", "bc:30:5b": "Dell",
    "c0:3f:d5": "Dell", "c4:cb:e1": "Dell", "c8:1f:66": "Dell",
    "cc:3d:82": "Dell", "d0:67:e5": "Dell", "d4:be:d9": "Dell",
    "d8:9e:f3": "Dell", "dc:a9:71": "Dell", "e0:db:55": "Dell",
    "e4:b9:7a": "Dell", "e8:b1:fc": "Dell", "ec:f4:bb": "Dell",
    "f0:1f:af": "Dell", "f4:8e:38": "Dell", "f8:db:88": "Dell",
    "fc:15:b4": "Dell",
    # HP
    "00:01:e6": "HP", "00:01:e7": "HP", "00:02:a5": "HP",
    "00:04:ea": "HP", "00:08:02": "HP", "00:0b:cd": "HP",
    "00:0e:7f": "HP", "00:10:83": "HP", "00:11:0a": "HP",
    "00:12:79": "HP", "00:13:21": "HP", "00:14:38": "HP",
    "00:15:60": "HP", "00:16:35": "HP", "00:17:08": "HP",
    "00:18:71": "HP", "00:19:bb": "HP", "00:1a:4b": "HP",
    "00:1b:78": "HP", "00:1c:c4": "HP", "00:1d:b3": "HP",
    "00:1e:0b": "HP", "00:1f:29": "HP", "00:21:5a": "HP",
    "00:22:64": "HP", "00:23:7d": "HP", "00:24:81": "HP",
    "00:25:b3": "HP", "00:26:55": "HP", "3c:d9:2b": "HP",
    "40:b0:34": "HP", "48:0f:cf": "HP", "4c:39:09": "HP",
    "50:65:f3": "HP", "54:04:a6": "HP", "58:20:b1": "HP",
    "5c:b9:01": "HP", "60:eb:69": "HP", "64:51:06": "HP",
    "68:b5:99": "HP", "6c:c2:17": "HP", "70:5a:b6": "HP",
    "74:46:a0": "HP", "78:48:59": "HP", "7c:2e:bd": "HP",
    "80:ce:62": "HP", "84:34:97": "HP", "88:51:fb": "HP",
    "8c:dc:d4": "HP", "90:1b:0e": "HP", "94:57:a5": "HP",
    "98:4b:e1": "HP", "9c:8e:99": "HP", "a0:1d:48": "HP",
    "a4:5d:36": "HP", "a8:97:dc": "HP", "ac:16:2d": "HP",
    "b0:5a:da": "HP", "b4:99:ba": "HP", "b8:ca:3a": "HP",
    "bc:ea:fa": "HP", "c0:3f:d5": "HP", "c4:34:6b": "HP",
    "c8:d3:ff": "HP", "cc:3d:82": "HP", "d0:bf:9c": "HP",
    "d4:c9:ef": "HP", "d8:d3:85": "HP", "dc:4a:3e": "HP",
    "e0:07:1b": "HP", "e4:11:5b": "HP", "e8:39:35": "HP",
    "ec:b1:d7": "HP", "f0:92:1c": "HP", "f4:ce:46": "HP",
    "f8:b1:56": "HP", "fc:15:b4": "HP",
    # Mikrotik
    "00:0c:42": "MikroTik", "2c:c8:1b": "MikroTik", "4c:5e:0c": "MikroTik",
    "6c:3b:6b": "MikroTik", "74:4d:28": "MikroTik", "b8:69:f4": "MikroTik",
    "cc:2d:e0": "MikroTik", "d4:ca:6d": "MikroTik", "dc:2c:6e": "MikroTik",
    "e4:8d:8c": "MikroTik",
    # Ubiquiti
    "00:15:6d": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:d6": "Ubiquiti",
    "0c:80:63": "Ubiquiti", "18:e8:29": "Ubiquiti", "24:a4:3c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti", "68:72:51": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "80:2a:a8": "Ubiquiti", "b4:fb:e4": "Ubiquiti", "dc:9f:db": "Ubiquiti",
    "e0:63:da": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    # Sony
    "00:01:4a": "Sony", "00:04:1f": "Sony", "00:0d:4b": "Sony",
    "00:13:a9": "Sony", "00:15:c1": "Sony", "00:19:4e": "Sony",
    "00:1a:80": "Sony", "00:1d:0d": "Sony", "00:1e:a9": "Sony",
    "00:24:be": "Sony", "00:25:e7": "Sony", "00:26:43": "Sony",
    "04:98:f3": "Sony", "10:4f:a8": "Sony", "18:00:2d": "Sony",
    "1c:a4:72": "Sony", "20:16:d8": "Sony", "28:3f:69": "Sony",
    "2c:85:7e": "Sony", "30:17:c8": "Sony", "34:c7:31": "Sony",
    "38:18:4c": "Sony", "3c:01:ef": "Sony", "40:b8:37": "Sony",
    "44:d8:84": "Sony", "48:5a:b6": "Sony", "4c:bc:98": "Sony",
    "50:2f:a8": "Sony", "54:42:49": "Sony", "58:17:0c": "Sony",
    "5c:f3:70": "Sony", "60:38:e0": "Sony", "64:d4:bd": "Sony",
    "68:86:a7": "Sony", "6c:ad:f8": "Sony", "70:2a:d5": "Sony",
    "74:e5:0b": "Sony", "78:84:3c": "Sony", "7c:1c:4e": "Sony",
    "80:4e:81": "Sony", "84:c7:ea": "Sony", "88:c9:e8": "Sony",
    "8c:64:a2": "Sony", "90:c1:15": "Sony", "94:ce:2c": "Sony",
    "98:0c:a5": "Sony", "9c:ad:97": "Sony", "a0:e4:53": "Sony",
    "a4:c3:f0": "Sony", "a8:e0:73": "Sony", "ac:9b:0a": "Sony",
    "b0:d0:9c": "Sony", "b4:52:7e": "Sony", "b8:8a:ec": "Sony",
    "bc:60:a7": "Sony", "c0:bd:d1": "Sony", "c4:85:08": "Sony",
    "c8:63:f1": "Sony", "cc:fb:65": "Sony", "d0:27:88": "Sony",
    "d4:e8:80": "Sony", "d8:d4:3c": "Sony", "dc:0b:34": "Sony",
    "e0:ae:5e": "Sony", "e4:8b:7f": "Sony", "e8:92:a4": "Sony",
    "ec:0e:c4": "Sony", "f0:bf:97": "Sony", "f4:f5:d8": "Sony",
    "f8:7b:7a": "Sony", "fc:0f:e6": "Sony",
    # LG
    "00:1e:75": "LG", "00:1f:6b": "LG", "00:21:fb": "LG",
    "00:24:83": "LG", "00:26:e2": "LG", "04:d6:aa": "LG",
    "08:55:31": "LG", "0c:48:85": "LG", "10:68:3f": "LG",
    "14:c1:4e": "LG", "18:67:b0": "LG", "1c:08:c1": "LG",
    "20:16:b9": "LG", "24:c6:96": "LG", "28:39:26": "LG",
    "2c:54:cf": "LG", "30:cd:a7": "LG", "34:fc:ef": "LG",
    "38:8b:59": "LG", "3c:bd:3e": "LG", "40:b0:fa": "LG",
    "44:4e:6d": "LG", "48:59:29": "LG", "4c:bc:a5": "LG",
    "50:55:27": "LG", "54:fc:f5": "LG", "58:a2:b5": "LG",
    "5c:f6:dc": "LG", "60:e3:ac": "LG", "64:99:5d": "LG",
    "68:3e:34": "LG", "6c:2f:2c": "LG", "70:2a:d5": "LG",
    "74:a7:22": "LG", "78:5d:c8": "LG", "7c:1c:68": "LG",
    "80:91:33": "LG", "84:25:19": "LG", "88:07:4b": "LG",
    "8c:3a:e3": "LG", "90:18:7c": "LG", "94:35:0a": "LG",
    "98:01:a7": "LG", "9c:02:98": "LG", "a0:39:f7": "LG",
    "a4:70:d6": "LG", "a8:16:d0": "LG", "ac:f1:df": "LG",
    "b0:39:56": "LG", "b4:e6:2d": "LG", "b8:ad:3e": "LG",
    "bc:f5:ac": "LG", "c0:97:27": "LG", "c4:36:6c": "LG",
    "c8:02:10": "LG", "cc:fa:00": "LG", "d0:13:fd": "LG",
    "d4:20:b0": "LG", "d8:13:99": "LG", "dc:0b:34": "LG",
    "e0:cb:ee": "LG", "e4:a7:c5": "LG", "e8:5b:5b": "LG",
    "ec:9b:f3": "LG", "f0:1c:13": "LG", "f4:6d:04": "LG",
    "f8:95:c7": "LG", "fc:f1:36": "LG",
}

# Cache untuk API lookup (hindari request berulang)
_vendor_cache = {}


def get_mac_vendor(mac):
    """Get vendor name from MAC address using local OUI lookup + API fallback"""
    if not mac or mac == "N/A":
        return "Unknown"

    mac_clean = mac.upper().replace("-", ":").strip()
    prefix8 = mac_clean[:8].lower()   # xx:xx:xx
    prefix6 = mac_clean[:5].lower()   # xx:xx (2 byte)

    # 1. Local OUI map (8-char prefix)
    for key, vendor in OUI_MAP.items():
        if prefix8 == key.lower():
            return vendor

    # 2. Cache check
    if prefix8 in _vendor_cache:
        return _vendor_cache[prefix8]

    # 3. API fallback (macvendors.com - gratis, no key)
    try:
        import urllib.request
        mac_query = mac_clean.replace(":", "%3A")
        url = f"https://api.macvendors.com/{mac_query}"
        req = urllib.request.Request(url, headers={"User-Agent": "WiFiMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            vendor = resp.read().decode("utf-8").strip()
            if vendor and len(vendor) < 60:
                _vendor_cache[prefix8] = vendor
                return vendor
    except Exception:
        pass

    _vendor_cache[prefix8] = "Unknown"
    return "Unknown"


# Cache hostname agar tidak query berulang
_hostname_cache = {}


def get_hostname(ip):
    """
    Resolve hostname dari IP — hanya pakai reverse DNS (cepat, <1 detik).
    Metode lambat (avahi, nmblookup, nmap) dijalankan di background via
    resolve_hostname_async() agar tidak memblokir scan ARP.

    Returns:
        Hostname string, atau ip itu sendiri kalau tidak ditemukan.
    """
    if ip in _hostname_cache:
        return _hostname_cache[ip]

    # Hanya reverse DNS di sini — cepat, tidak blocking
    name = _try_reverse_dns(ip)
    result = name if name else ip
    _hostname_cache[ip] = result
    return result


def resolve_hostname_async(ip, on_done=None):
    """
    Resolve hostname lengkap di background thread (avahi → nmblookup → nmap).
    Dipanggil setelah scan ARP selesai agar tidak memperlambat deteksi device.

    Args:
        ip      : IP yang mau di-resolve
        on_done : callback(ip, hostname) dipanggil setelah resolve selesai
    """
    def _worker():
        # Skip kalau sudah ada nama yang bukan IP di cache
        cached = _hostname_cache.get(ip, ip)
        if cached != ip:
            return  # Sudah punya nama, tidak perlu resolve lagi

        name = _try_mdns(ip) or _try_netbios(ip) or _try_nmap(ip)
        if name and name != ip:
            _hostname_cache[ip] = name
            if on_done:
                on_done(ip, name)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _try_reverse_dns(ip):
    """Reverse DNS lookup via socket — paling cepat, tapi tidak selalu ada"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            # Ambil bagian pertama dari FQDN (misal: android-abc.local → android-abc)
            short = hostname.split(".")[0]
            return short if short else hostname
    except Exception:
        pass
    return None


def _try_mdns(ip):
    """
    mDNS lookup via avahi-resolve — bagus untuk Android, iOS, Mac, Linux
    Device yang pakai Bonjour/mDNS biasanya punya nama seperti 'iPhone-banh.local'
    """
    try:
        result = subprocess.run(
            ["avahi-resolve", "--address", ip],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output: "192.168.1.5\tiphone-banh.local"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                name = parts[-1].rstrip(".")
                short = name.split(".")[0]
                return short if short else name
    except Exception:
        pass
    return None


def _try_netbios(ip):
    """
    NetBIOS lookup via nmblookup — bagus untuk Windows
    Nama komputer Windows biasanya muncul di sini
    """
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                # Cari baris yang berisi nama (bukan group, bukan <00>)
                if "<00>" in line and "GROUP" not in line and "IS" not in line:
                    name = line.split()[0].strip()
                    if name and name != ip:
                        return name
    except Exception:
        pass
    return None


def _try_nmap(ip):
    """
    nmap -sn sebagai fallback terakhir — lebih lambat tapi paling lengkap
    Hanya dipakai kalau semua metode lain gagal
    """
    try:
        result = subprocess.run(
            ["nmap", "-sn", "--host-timeout", "2s", ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    # Format: "Nmap scan report for hostname (192.168.1.5)"
                    # atau:   "Nmap scan report for 192.168.1.5"
                    part = line.replace("Nmap scan report for", "").strip()
                    if "(" in part:
                        name = part.split("(")[0].strip()
                        if name and name != ip:
                            return name
    except Exception:
        pass
    return None


def get_local_network():
    """Get local network CIDR (e.g., 192.168.1.0/24)"""
    if NETIFACES_AVAILABLE:
        try:
            gateways = netifaces.gateways()
            default_iface = gateways['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(default_iface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            # Convert to CIDR
            parts = netmask.split('.')
            cidr = sum(bin(int(x)).count('1') for x in parts)
            network = '.'.join(ip.split('.')[:3]) + '.0/' + str(cidr)
            return network, default_iface
        except Exception:
            pass

    # Fallback: try ip route
    try:
        result = subprocess.check_output(['ip', 'route'], text=True)
        for line in result.splitlines():
            if 'src' in line and 'default' not in line:
                parts = line.split()
                network = parts[0]
                iface = parts[parts.index('dev') + 1] if 'dev' in parts else 'eth0'
                return network, iface
    except Exception:
        pass

    return "192.168.1.0/24", "wlan0"


def scan_network_arp(network, iface=None):
    """Scan network using ARP requests"""
    devices = []

    if not SCAPY_AVAILABLE:
        return scan_network_ping(network)

    try:
        conf.verb = 0
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        kwargs = {"timeout": 3, "verbose": False}
        if iface:
            kwargs["iface"] = iface

        answered_list = srp(arp_request_broadcast, **kwargs)[0]

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            hostname = get_hostname(ip)
            vendor = get_mac_vendor(mac)
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "status": "online",
                "last_seen": datetime.now().strftime("%H:%M:%S"),
                "open_ports": [],
                "threat_level": "safe"
            })
    except Exception as e:
        print(f"[Scanner] ARP scan error: {e}")
        return scan_network_ping(network)

    return devices


def scan_network_ping(network):
    """Fallback: scan using ping sweep"""
    devices = []
    base_ip = '.'.join(network.split('.')[:3])

    def ping_host(ip):
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                hostname = get_hostname(ip)
                devices.append({
                    "ip": ip,
                    "mac": "N/A",
                    "hostname": hostname,
                    "vendor": "Unknown",
                    "status": "online",
                    "last_seen": datetime.now().strftime("%H:%M:%S"),
                    "open_ports": [],
                    "threat_level": "safe"
                })
        except Exception:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=ping_host, args=(ip,))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=3)

    return devices


class NetworkScanner:
    """
    Scanner perangkat jaringan yang berjalan di background thread.

    Cara kerja:
    1. Deteksi otomatis network CIDR dan interface aktif saat start()
    2. Kirim ARP broadcast ke seluruh subnet setiap scan_interval detik
    3. Resolve hostname dan vendor untuk setiap perangkat yang ditemukan
    4. Panggil on_update callback setiap ada perubahan daftar perangkat

    Contoh penggunaan:
        scanner = NetworkScanner()
        scanner.on_update = lambda devices: print(devices)
        scanner.start()

    ---
    Background-threaded network device scanner.

    How it works:
    1. Auto-detects network CIDR and active interface on start()
    2. Sends ARP broadcast to entire subnet every scan_interval seconds
    3. Resolves hostname and vendor for each discovered device
    4. Calls on_update callback whenever device list changes

    Example:
        scanner = NetworkScanner()
        scanner.on_update = lambda devices: print(devices)
        scanner.start()
    """

    def __init__(self):
        self.devices = {}           # {ip: device_dict} — state perangkat saat ini
        self.network = None         # CIDR string, misal "192.168.1.0/24"
        self.iface = None           # Nama interface, misal "wlan0"
        self.running = False
        self.scan_interval = 30     # Detik antar scan otomatis
        self._lock = threading.Lock()
        self.on_update = None       # Callback dipanggil setelah setiap scan selesai

    def start(self):
        """
        Deteksi jaringan lokal lalu mulai loop scan di background thread.
        Scan pertama langsung dijalankan, lalu berulang tiap scan_interval detik.

        ---
        Detect local network then start the scan loop in a background thread.
        First scan runs immediately, then repeats every scan_interval seconds.
        """
        self.network, self.iface = get_local_network()
        print(f"[Scanner] Network: {self.network} | Interface: {self.iface}")
        self.running = True
        thread = threading.Thread(target=self._scan_loop, daemon=True)
        thread.start()

    def stop(self):
        """Hentikan loop scan. / Stop the scan loop."""
        self.running = False

    def _scan_loop(self):
        """
        Loop utama yang berjalan di background thread.
        Jalankan scan, tunggu scan_interval detik, ulangi.

        ---
        Main loop running in background thread.
        Run scan, wait scan_interval seconds, repeat.
        """
        while self.running:
            self._do_scan()
            time.sleep(self.scan_interval)

    def _do_scan(self):
        """
        Lakukan satu siklus scan ARP ke seluruh subnet.

        Proses:
        1. Tandai semua perangkat yang dikenal sebagai "offline"
        2. Kirim ARP broadcast, kumpulkan respons
        3. Update state perangkat — yang merespons jadi "online"
        4. Pertahankan threat_level dan open_ports dari scan sebelumnya
        5. Panggil on_update callback dengan daftar terbaru

        ---
        Perform one ARP scan cycle across the entire subnet.

        Process:
        1. Mark all known devices as "offline"
        2. Send ARP broadcast, collect responses
        3. Update device state — responders become "online"
        4. Preserve threat_level and open_ports from previous scan
        5. Call on_update callback with updated device list
        """
        print(f"[Scanner] Scanning {self.network}...")
        new_devices = scan_network_arp(self.network, self.iface)

        with self._lock:
            # Tandai semua offline dulu, nanti yang aktif akan di-update
            for ip in self.devices:
                self.devices[ip]["status"] = "offline"

            for dev in new_devices:
                ip = dev["ip"]
                if ip in self.devices:
                    # Pertahankan data yang tidak berubah antar scan
                    dev["threat_level"] = self.devices[ip].get("threat_level", "safe")
                    dev["open_ports"]   = self.devices[ip].get("open_ports", [])
                self.devices[ip] = dev

        print(f"[Scanner] Found {len(new_devices)} devices")

        if self.on_update:
            self.on_update(self.get_devices())

        # Resolve hostname lengkap di background untuk setiap device baru
        # Hasilnya akan update cache dan push update ke client saat scan berikutnya
        for dev in new_devices:
            def _push_hostname(ip, hostname):
                with self._lock:
                    if ip in self.devices:
                        self.devices[ip]["hostname"] = hostname
                if self.on_update:
                    self.on_update(self.get_devices())
            resolve_hostname_async(dev["ip"], on_done=_push_hostname)

    def get_devices(self):
        """
        Ambil snapshot daftar perangkat saat ini (thread-safe).

        Returns:
            List dict perangkat. Setiap dict berisi:
            ip, mac, hostname, vendor, status, last_seen, open_ports, threat_level

        ---
        Get a thread-safe snapshot of the current device list.

        Returns:
            List of device dicts. Each dict contains:
            ip, mac, hostname, vendor, status, last_seen, open_ports, threat_level
        """
        with self._lock:
            return list(self.devices.values())

    def set_threat(self, ip, level):
        """
        Set level ancaman untuk perangkat tertentu.

        Args:
            ip    : IP perangkat
            level : "safe" | "warning" | "danger" | "critical"

        ---
        Set the threat level for a specific device.

        Args:
            ip    : device IP address
            level : "safe" | "warning" | "danger" | "critical"
        """
        with self._lock:
            if ip in self.devices:
                self.devices[ip]["threat_level"] = level

    def force_scan(self):
        """
        Paksa scan langsung tanpa menunggu interval berikutnya.
        Dijalankan di thread terpisah agar tidak memblokir request HTTP.

        ---
        Force an immediate scan without waiting for the next interval.
        Runs in a separate thread to avoid blocking HTTP requests.
        """
        thread = threading.Thread(target=self._do_scan, daemon=True)
        thread.start()
