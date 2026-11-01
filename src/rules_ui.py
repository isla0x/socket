"""Table editor for the existing rule format; no changes to packet hooks."""
import json
import re
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QComboBox, QCheckBox, QLineEdit, QPushButton, QDialogButtonBox,
    QFileDialog, QHeaderView, QAbstractItemView)
from packet import validate_rules, compile_rules


class RulesDialog(QDialog):
    def __init__(self, rules, parent=None, direction='RX', contains='', embedded=False):
        super().__init__(parent)
        self.embedded = embedded
        if embedded:
            self.setWindowFlags(Qt.WindowType.Widget)
        self.setWindowTitle('간편 치환 규칙')
        self.resize(1150, 620)
        self.result_value = None
        self.encoding = getattr(parent, 'encoding', 'cp949')
        layout = QVBoxLayout(self)
        hint = QLabel('① 방향·거래 코드·찾을 값·바꿀 값 입력 → 추가 → ② 저장 후 자동 치환 켜기\n'
                      '거래 코드는 패킷에 포함된 문자열입니다. 쉼표로 여러 개 입력하면 각각 등록됩니다. 규칙은 위에서부터 적용됩니다.')
        hint.setWordWrap(True)
        if embedded:
            hint.setText('규칙 추가 → 저장 · 여러 거래 코드는 쉼표로 구분 · 표에서 수정/삭제')
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.direction = self.combo(['RX', 'TX', 'ANY'], direction)
        row.addWidget(self.direction)
        self.codes = QLineEdit(contains)
        self.codes.setPlaceholderText('거래 코드: DDAZ00032, DDAZ80028')
        self.before = QLineEdit()
        self.before.setPlaceholderText('찾을 값: user01')
        self.after = QLineEdit()
        self.after.setPlaceholderText('바꿀 값: user002')
        for widget in (self.codes, self.before, self.after):
            row.addWidget(widget, 1)
        self.add_button(row, '추가', self.add_quick)
        layout.addLayout(row)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(['사용', '방향', '포함 조건 / 거래 코드', '찾을 값', '바꿀 값', '모두', '길이 변경', '형식'])
        if embedded:
            self.table.setHorizontalHeaderItem(2, QTableWidgetItem('거래 코드 / 조건'))
            for col in (5, 6, 7):
                self.table.setColumnHidden(col, True)
            self.table.setToolTip('모두 치환·길이 변경·문자열/Hex 형식은 상단 간편 치환 규칙 창에서 변경할 수 있습니다.')
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        if embedded:
            self.table.setMinimumHeight(110)
        for col in range(8):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch if col in (2, 3, 4) else QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        for text, callback in [('선택 삭제', self.delete_selected), ('위로', lambda: self.move(-1)),
                               ('아래로', lambda: self.move(1)), ('규칙 불러오기', self.import_rules),
                               ('규칙 파일 저장', self.export_rules)]:
            self.add_button(actions, text, callback)
        actions.addStretch()
        layout.addLayout(actions)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet('color:#a33b24')
        layout.addWidget(self.error)
        note = QLabel('길이가 다른 값은 추가할 때 자동으로 「길이 변경」을 체크합니다. 고정 폭 필드는 위치가 밀릴 수 있습니다.\n'
                      '저장은 새로 발생하는 패킷부터 적용합니다. 취소하면 현재 규칙을 유지합니다.')
        note.setWordWrap(True)
        layout.addWidget(note)
        if embedded:
            note.hide()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText('저장 후 자동 치환 켜기')
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText('취소')
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        if embedded:
            buttons.button(QDialogButtonBox.StandardButton.Cancel).hide()
        layout.addWidget(buttons)
        self.populate(rules)

    @staticmethod
    def combo(values, selected):
        widget = QComboBox()
        labels = {'TX':'요청', 'RX':'응답', 'ANY':'요청 + 응답'}
        for value in values:
            widget.addItem(labels.get(value,value),value)
        widget.setCurrentIndex(widget.findData(selected))
        return widget

    @staticmethod
    def add_button(row, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        row.addWidget(button)

    def populate(self, rules):
        self.table.setRowCount(0)
        for rule in rules:
            self.append(rule)

    def reject(self):
        if not self.embedded:
            super().reject()

    def append(self, rule):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key, default in [(0, 'enabled', True), (5, 'all', False), (6, 'allow_resize', False)]:
            box = QCheckBox()
            box.setChecked(rule.get(key, default))
            self.table.setCellWidget(row, col, box)
        self.table.setCellWidget(row, 1, self.combo(['RX', 'TX', 'ANY'], rule.get('direction', 'RX')))
        kind = rule.get('kind', 'hex')
        for col, value in [(2, rule.get('contains', '')), (3, rule.get('find_text' if kind == 'text' else 'find_hex', '')),
                           (4, rule.get('replace_text' if kind == 'text' else 'replace_hex', ''))]:
            item = QTableWidgetItem(value)
            if col == 2:
                item.setData(Qt.ItemDataRole.UserRole, dict(rule))
            self.table.setItem(row, col, item)
        fmt = 'hex' if kind == 'hex' else rule.get('encoding', 'cp949')
        self.table.setCellWidget(row, 7, self.combo(['cp949', 'utf-8', 'ascii', 'hex'], fmt))

    def collect(self):
        rules = []
        for row in range(self.table.rowCount()):
            rule = dict(self.table.item(row, 2).data(Qt.ItemDataRole.UserRole) or {})
            fmt = self.table.cellWidget(row, 7).currentText()
            kind = 'hex' if fmt == 'hex' else 'text'
            for key in ('find_text', 'replace_text', 'find_hex', 'replace_hex'):
                rule.pop(key, None)
            rule.update(direction=self.table.cellWidget(row, 1).currentData(),
                        contains=self.table.item(row, 2).text(), kind=kind,
                        encoding='cp949' if kind == 'hex' else fmt)
            rule['find_text' if kind == 'text' else 'find_hex'] = self.table.item(row, 3).text()
            rule['replace_text' if kind == 'text' else 'replace_hex'] = self.table.item(row, 4).text()
            rule.setdefault('name', rule['contains'] + ' 치환')
            for col, key in [(0, 'enabled'), (5, 'all'), (6, 'allow_resize')]:
                rule[key] = self.table.cellWidget(row, col).isChecked()
            rules.append(rule)
        return rules

    def checked_rules(self):
        rules = validate_rules({'rules': self.collect()})
        compile_rules(rules, self.encoding)
        return rules

    def add_quick(self):
        try:
            before, after = self.before.text(), self.after.text()
            resize = len(before.encode('cp949')) != len(after.encode('cp949'))
            codes = list(dict.fromkeys(re.split(r'[,，;\s]+', self.codes.text().strip())))
            if not any(codes):
                raise ValueError('적용할 거래 코드 / 포함 조건을 입력하세요.')
            added = validate_rules({'rules': [dict(name=code + ' ' + before + ' → ' + after,
                direction=self.direction.currentData(), contains=code, kind='text', encoding='cp949',
                find_text=before, replace_text=after, allow_resize=resize, all=True, enabled=True) for code in codes if code]})
            if self.table.rowCount() + len(added) > 100:
                raise ValueError('규칙은 최대 100개입니다.')
            for rule in added:
                self.append(rule)
            self.error.setText(f'{len(added)}개 추가했습니다. 아래 저장 버튼을 눌러 적용하세요.')
        except (ValueError, UnicodeError) as exc:
            self.error.setText(str(exc))

    def delete_selected(self):
        for row in sorted({index.row() for index in self.table.selectionModel().selectedRows()}, reverse=True):
            self.table.removeRow(row)

    def move(self, step):
        row = self.table.currentRow()
        dest = row + step
        if 0 <= row < self.table.rowCount() and 0 <= dest < self.table.rowCount():
            rules = self.collect()
            rules[row], rules[dest] = rules[dest], rules[row]
            self.populate(rules)
            self.table.selectRow(dest)

    def save(self):
        try:
            self.table.setFocus()  # Commit the active cell editor before reading.
            self.result_value = self.checked_rules()
            if self.embedded:
                self.accepted.emit()
            else:
                self.accept()
        except (ValueError, UnicodeError) as exc:
            self.error.setText(str(exc).replace('allow_resize: true', '「길이 변경」 체크'))

    def import_rules(self):
        path, _ = QFileDialog.getOpenFileName(self, '규칙 불러오기', '', 'JSON (*.json)')
        if path:
            try:
                if Path(path).stat().st_size > 200_000:
                    raise ValueError('규칙 파일은 최대 200 KB입니다.')
                rules = validate_rules(json.loads(Path(path).read_text(encoding='utf-8-sig')))
                compile_rules(rules, self.encoding)
                self.populate(rules)
                self.error.setText('파일의 규칙으로 표를 교체했습니다. 저장해야 적용됩니다.')
            except Exception as exc:
                self.error.setText(str(exc))

    def export_rules(self):
        try:
            rules = self.checked_rules()
            path, _ = QFileDialog.getSaveFileName(self, '규칙 파일 저장', 'rules.json', 'JSON (*.json)')
            if path:
                Path(path).write_text(json.dumps({'rules': rules}, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as exc:
            self.error.setText(str(exc))
