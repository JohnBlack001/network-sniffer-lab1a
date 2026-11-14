"""Windows/Npcap network sniffer entry point."""

import sys

from PySide6.QtWidgets import QApplication

from sniffer.ui import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetScope")
    app.setOrganizationName("Network Lab")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
