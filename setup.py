from setuptools import setup

APP = ['transmission_cleanup_app.py']
DATA_FILES = [('', ['app_icon.png'])]
OPTIONS = {
    'argv_emulation': False,
    'plist': {
        'CFBundleName': 'Transmission Cleanup',
        'CFBundleDisplayName': 'Transmission Cleanup',
        'CFBundleIdentifier': 'com.transmissioncleanup.app',
        'CFBundleVersion': '1.3.0',
        'CFBundleShortVersionString': '1.3.0',
        'NSHumanReadableCopyright': 'Copyright Macify Software © 2025',
        'NSHighResolutionCapable': True,
    },
    'packages': ['PyQt5'],
    'includes': ['PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'sip', 'PyQt5_sip'],
    'excludes': ['matplotlib', 'numpy', 'pandas', 'scipy', 'cryptography'],
    'frameworks': [],
    'iconfile': 'app_icon.icns',
}

setup(
    app=APP,
    name='Transmission Cleanup',
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
