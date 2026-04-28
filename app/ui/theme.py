MODERN_QSS = """
QMainWindow, QWidget {
    background: #121316;
    color: #ECEFF4;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 14px;
}

QLabel {
    color: #E6E9EF;
}

QLineEdit, QComboBox, QTextEdit, QTableWidget, QTreeWidget {
    background: #1A1D23;
    border: 1px solid #2A2F3A;
    border-radius: 10px;
    padding: 7px 10px;
    color: #F2F4F8;
    selection-background-color: #2B6CF6;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QTreeWidget:focus, QTableWidget:focus {
    border: 1px solid #4A84FF;
}

QPushButton {
    background: #222733;
    border: 1px solid #31384A;
    border-radius: 10px;
    padding: 8px 14px;
    color: #EAF0FF;
}

QPushButton:hover {
    background: #2A3243;
    border: 1px solid #4A84FF;
}

QPushButton:pressed {
    background: #1C2230;
}

QHeaderView::section {
    background: #202532;
    color: #EAF0FF;
    border: none;
    border-right: 1px solid #2E3546;
    border-bottom: 1px solid #2E3546;
    padding: 8px;
}

QTableWidget::item, QTreeWidget::item {
    padding: 6px;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background: #2A4EA8;
    color: #FFFFFF;
}

QMenu {
    background: #1B1F28;
    border: 1px solid #31384A;
    border-radius: 8px;
    padding: 6px;
}

QMenu::item {
    padding: 8px 14px;
    border-radius: 6px;
}

QMenu::item:selected {
    background: #2B6CF6;
}

QSplitter::handle {
    background: #1D2330;
    width: 6px;
}

QScrollBar:vertical {
    background: #141821;
    width: 11px;
    margin: 3px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #2D3446;
    min-height: 25px;
    border-radius: 5px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""
