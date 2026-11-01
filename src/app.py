from __future__ import annotations

import json
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QEvent
from PySide6.QtGui import QColor, QFont, QFontDatabase, QTextCursor, QKeyEvent, QAction, QBrush, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget, QToolButton, QMenu,
)

from backend import Backend
from rules_ui import RulesDialog
from packet import (DEMO_FIELDS, MAX_EVENTS, Packet, apply_rules, edit_field, field_value,
                    hexdump, load_session, parse_hex, parse_visible, save_session,
                    transaction, validate_fields, validate_rules, visible, replace_bytes,
                    compile_rules, validate_lengths, update_lengths)

ASSETS = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
MONO = QFont('Consolas', 11)
EDIT_LIMIT = 65_536
MARKERS = [('', '없음'), ('#fff0ad','노랑'), ('#c9efd5','초록'), ('#cce5ff','파랑'), ('#efdbff','보라'), ('#ffd6df','분홍')]
LOGGER = logging.getLogger('socket-inspector')

STYLE = '''
QMainWindow,QDialog { background:#f1f4f8; color:#172538; }
QWidget { font-family:"Segoe UI","Malgun Gothic"; font-size:13px; }
QLabel#title { font-size:23px; font-weight:600; color:#152f52; }
QLabel#mode { color:#315580; background:#e4ebf6; border-radius:5px; padding:5px 10px; }
QLabel#hint { color:#52667e; }
QLabel#detailTitle { font-size:17px; font-weight:600; }
QLabel#manualBanner { padding:10px; border:1px solid #d7e0eb; border-radius:5px; background:#eaf1fb; color:#173d6d; }
QPushButton { background:white; border:1px solid #ccd5e1; border-radius:5px; padding:7px 12px; }
QPushButton:hover { background:#eaf1fb; border-color:#7f9fc9; }
QPushButton:disabled { color:#8e9aab; background:#f0f2f6; }
QPushButton#primary { background:#245fae; color:white; border:1px solid #245fae; font-weight:600; }
QPushButton#primary:hover { background:#1b4d91; }
QPushButton#primary:disabled { background:#b5c7df; border-color:#b5c7df; }
QToolButton#primary { background:#245fae; color:white; border:1px solid #245fae; border-radius:5px; padding:7px 12px; }
QToolButton#primary:disabled { background:#b5c7df; border-color:#b5c7df; }
QLineEdit,QComboBox,QSpinBox { background:white; color:#172538; border:1px solid #ccd5e1; border-radius:4px; padding:5px; }
QPlainTextEdit { background:white; color:#172538; border:1px solid #d5dde8; border-radius:4px; selection-background-color:#c8ddfb; }
QPlainTextEdit[readOnly="true"] { background:#f6f8fb; }
QGroupBox { border:1px solid #d8e0eb; border-radius:6px; margin-top:10px; padding:12px 10px 8px; background:#fafbfd; }
QGroupBox::title { subcontrol-origin:margin; left:10px; color:#52667e; padding:0 5px; }
QTableWidget { background:white; alternate-background-color:#f7f9fc; border:1px solid #d8e0eb; gridline-color:#e5eaf1; selection-background-color:#dceaff; selection-color:#163d6c; }
QHeaderView::section { background:#f1f5fa; color:#50657d; border:0; border-bottom:1px solid #d8e0eb; padding:7px; }
QTabWidget::pane { background:white; border:1px solid #d8e0eb; border-radius:4px; }
QTabBar::tab { background:#e8edf4; padding:9px 16px; margin-right:3px; color:#52667e; }
QTabBar::tab:selected { background:white; color:#245fae; border-bottom:2px solid #245fae; }
QSplitter::handle { background:#e4eaf2; }
QStatusBar { color:#52667e; }
QCheckBox { spacing:6px; }
'''


def button(text, callback, primary=False):
    b = QPushButton(text)
    if primary:
        b.setObjectName('primary')
    b.clicked.connect(callback)
    return b


def readonly_item(value):
    item = QTableWidgetItem(str(value))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


class JsonDialog(QDialog):
    def __init__(self, title, value, validator, parent):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(780, 600)
        self.result_value = None
        layout = QVBoxLayout(self)
        self.editor = QPlainTextEdit(json.dumps(value, ensure_ascii=False, indent=2))
        self.editor.setFont(MONO)
        layout.addWidget(self.editor)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet('color:#a33b24;')
        layout.addWidget(self.error)
        row = QHBoxLayout()
        row.addWidget(button('JSON 불러오기', self.open_file))
        row.addWidget(button('JSON 저장', self.save_file))
        row.addStretch()
        controls = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        controls.accepted.connect(lambda: self.apply(validator))
        controls.rejected.connect(self.reject)
        row.addWidget(controls)
        layout.addLayout(row)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, 'JSON 불러오기', '', 'JSON (*.json)')
        if path:
            try:
                if Path(path).stat().st_size > 200_000:
                    raise ValueError('설정 JSON은 최대 200 KB입니다.')
                self.editor.setPlainText(Path(path).read_text(encoding='utf-8-sig'))
            except Exception as e:
                self.error.setText(str(e))

    def save_file(self):
        try:
            value = json.loads(self.editor.toPlainText())
            path, _ = QFileDialog.getSaveFileName(self, 'JSON 저장', '', 'JSON (*.json)')
            if path:
                Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as e:
            self.error.setText(str(e))

    def apply(self, validator):
        try:
            self.result_value = validator(json.loads(self.editor.toPlainText()))
            self.accept()
        except Exception as e:
            self.error.setText(str(e))


class Window(QMainWindow):
    def __init__(self, start_demo=True):
        super().__init__()
        self.setWindowTitle('Socket Inspector v3.2.4 — 규칙 삭제 동기화')
        self.profile_state = {}
        self.active_profile = 'kyobo'
        self.resize(1720, 960)
        self.setMinimumSize(1050, 720)
        self.setStyleSheet(STYLE)
        self.packets = []
        self.by_id = {}
        self.current = None
        self.updating = False
        self.mode = 'demo'
        self.fields = []
        self.rules = []
        self.length_fields = []
        self.batch = False
        self.recent_packets = {}
        self.filter_active = False
        self.capture_sequence = 0
        self.encoding = 'cp949'
        self.session_dirty = False
        self.backend = Backend()
        self.backend.packet_received.connect(self.receive)
        self.backend.settled.connect(self.settled)
        self.backend.log.connect(self.log)
        self.backend.connection.connect(self.connection_changed)
        self.backend.applications.connect(self.apps_loaded)
        self.backend.prepared.connect(self.prepared)
        self.build_ui()
        QApplication.instance().installEventFilter(self)
        self.configure()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(250)
        self.display_timer = QTimer(self)
        self.display_timer.timeout.connect(self.flush_display)
        self.display_timer.start(100)
        if start_demo:
            self.intercept.setChecked(False)
            for _ in range(3):
                self.add_demo()
            self.add_demo()

    def build_ui(self):
        shell = QWidget()
        self.setCentralWidget(shell)
        layout = QVBoxLayout(shell)
        layout.setContentsMargins(18, 14, 18, 10)
        layout.setSpacing(10)
        top = QHBoxLayout()
        title = QLabel('Socket Inspector')
        title.setObjectName('title')
        self.mode_label = QLabel('DEMO · 실제 통신 없음')
        self.mode_label.setObjectName('mode')
        top.addWidget(title)
        top.addWidget(self.mode_label)
        self.capture_enabled = QCheckBox('캡처 ON')
        self.capture_enabled.setChecked(True)
        top.addWidget(self.capture_enabled)
        top.addStretch()
        self.demo_button = button('데모 패킷 추가', self.add_demo)
        top.addWidget(self.demo_button)
        top.addWidget(button('세션 열기', self.open_session))
        top.addWidget(button('세션 저장', self.save_session))
        top.addWidget(button('간편 치환 규칙', self.edit_rules))
        top.addWidget(button('목록 비우기 (Ctrl+X)', self.clear_packets))
        top.addWidget(button('고급 설정', self.toggle_advanced))
        layout.addLayout(top)

        connection = QGroupBox('Frida 연결 · 16.x')
        conn = QHBoxLayout(connection)
        self.profile = QComboBox()
        self.profile.addItem('교보 · 기존 방식', 'kyobo')
        self.profile.addItem('신영 · 실기기 검증 전', 'shinyoung')
        conn.addWidget(QLabel('대상 앱'))
        conn.addWidget(self.profile)
        self.diagnostic = QComboBox()
        self.diagnostic.addItem('① 연결만 검사 · 캡처 없음', 'attach')
        self.diagnostic.addItem('② Java만 검사 · 후크 없음', 'java')
        self.diagnostic.addItem('③ 패킷 캡처 · 기존 어댑터', 'capture')
        self.diagnostic.hide()
        conn.addWidget(self.diagnostic)
        self.address = QComboBox()
        self.address.setEditable(True)
        self.address.addItems(['USB', '127.0.0.1:27042'])
        self.address.setMaximumWidth(190)
        self.address.setToolTip('USB 또는 Frida 서버 주소 host:port')
        self.target = QComboBox()
        self.target.setEditable(True)
        self.target.setEditText('kr.com.wink')
        self.target.setMinimumWidth(260)
        self.target.lineEdit().setPlaceholderText('앱 패키지명 / 프로세스명 / PID')
        self.spawn = QCheckBox('시작하며 연결')
        conn.addWidget(QLabel('기기'))
        conn.addWidget(self.address)
        conn.addWidget(QLabel('앱'))
        conn.addWidget(self.target, 1)
        self.list_apps_button = button('앱 목록', self.list_apps)
        conn.addWidget(self.list_apps_button)
        conn.addWidget(self.spawn)
        self.connect_button = QToolButton()
        self.connect_button.setObjectName('primary')
        recommended = QAction('연결 · 캡처 시작',self)
        recommended.triggered.connect(self.connect_recommended)
        self.connect_button.setDefaultAction(recommended)
        self.connect_button.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        menu = QMenu(self.connect_button)
        manual = menu.addAction('현재 설정으로 일반 연결')
        manual.triggered.connect(self.connect_live)
        self.connect_button.setMenu(menu)
        self.disconnect_button = button('연결 해제', self.disconnect_live)
        self.disconnect_button.setEnabled(False)
        conn.addWidget(self.connect_button)
        conn.addWidget(self.disconnect_button)
        layout.addWidget(connection)

        capture = QHBoxLayout()
        self.intercept = QCheckBox('보내기 전 편집')
        self.intercept.setChecked(False)
        self.tx = QCheckBox('요청 중단')
        self.rx = QCheckBox('응답 중단')
        self.tx.setChecked(True)
        self.rx.setChecked(False)
        self.break_filter = QLineEdit()
        self.break_filter.setPlaceholderText('중단 조건: 원문에 포함된 문자열 (빈칸 = 전체)')
        self.timeout = QSpinBox()
        self.timeout.setRange(3, 300)
        self.timeout.setValue(60)
        self.timeout.setSuffix(' 초')
        self.source = QComboBox()
        self.source.addItem('요청: 헤더 + 본문', 'packet')
        self.source.addItem('요청: 암호화 전 본문', 'encrypt')
        capture.addWidget(self.intercept)
        capture.addWidget(self.tx)
        capture.addWidget(self.rx)
        capture.addWidget(self.break_filter, 1)
        capture.addWidget(QLabel('대기'))
        capture.addWidget(self.timeout)
        capture.addWidget(self.source)
        self.pending_button = button('대기 패킷 보기 (0)', self.show_pending)
        capture.addWidget(self.pending_button)
        capture.addWidget(button('모두 원본 진행', self.release_all))
        layout.addLayout(capture)
        self.advanced_panel=QWidget()
        options = QHBoxLayout(self.advanced_panel)
        options.setContentsMargins(0,0,0,0)
        self.compatibility = QCheckBox('기존 코드 사전 설정')
        self.compatibility.setToolTip('사용자가 제공한 android.js의 사전 설정만 같은 스크립트에 포함합니다. 기존 Frida 명령은 종료하고 이 프로그램만 연결하세요.')
        options.addWidget(self.compatibility)
        self.auto_rules = QCheckBox('자동 치환 (0)')
        self.auto_rules.setEnabled(False)
        options.addWidget(self.auto_rules)
        options.addWidget(button('치환 규칙', self.edit_rules))
        options.addWidget(button('필드 정의', self.edit_schema))
        self.allow_resize = QCheckBox('가변 길이 허용')
        options.addWidget(self.allow_resize)
        options.addWidget(button('길이 정보', self.edit_length_fields))
        self.group_repeats = QCheckBox('반복 묶기')
        self.group_repeats.setChecked(True)
        options.addWidget(self.group_repeats)
        self.length_note = QLabel('캡처는 항상 동작 · 일시중단은 편집용')
        self.length_note.setObjectName('hint')
        options.addWidget(self.length_note)
        options.addStretch()
        layout.addWidget(self.advanced_panel)
        self.advanced_panel.hide()
        self.profile.currentIndexChanged.connect(self.change_profile)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 7, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText('목록 검색: 거래 코드 / 문자열 / Hex / 상태')
        self.search.textChanged.connect(self.filter_rows)
        lv.addWidget(self.search)
        nav=QHBoxLayout()
        nav.addWidget(button('↑ 이전 패킷', lambda:self.navigate_packet(-1)))
        nav.addWidget(button('↓ 다음 패킷', lambda:self.navigate_packet(1)))
        nav.addWidget(QLabel('↑/↓ · 입력 중에는 Alt+↑/↓'))
        nav.addStretch()
        lv.addLayout(nav)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(['#', '시각', '방향', '거래 코드(추정)', '크기', '수집 지점', '상태'])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setColumnHidden(5, True)  # Full stage is displayed in the inspector header.
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column,width in enumerate((45,110,55,120,70,80,140)):
            self.table.setColumnWidth(column,width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.select_packet)
        lv.addWidget(self.table, 1)
        self.table.setColumnWidth(0,65)
        legend = QLabel('Ctrl+1 노랑 · 2 초록 · 3 파랑 · 4 보라 · 5 분홍\n같은 단축키를 다시 누르면 색상 해제')
        legend.setObjectName('hint')
        lv.addWidget(legend)
        self.count_label = QLabel('0건')
        self.count_label.setObjectName('hint')
        lv.addWidget(self.count_label)
        splitter.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(7, 0, 0, 0)
        heading = QHBoxLayout()
        self.detail_title = QLabel('패킷을 선택하세요')
        self.detail_title.setObjectName('detailTitle')
        heading.addWidget(self.detail_title, 1)
        self.encoding_select = QComboBox()
        self.encoding_select.addItem('MS949 / CP949', 'cp949')
        self.encoding_select.addItem('UTF-8', 'utf-8')
        self.encoding_select.addItem('ASCII', 'ascii')
        self.encoding_select.currentIndexChanged.connect(self.change_encoding)
        heading.addWidget(self.encoding_select)
        rv.addLayout(heading)
        self.detail_meta = QLabel('')
        self.detail_meta.setObjectName('hint')
        self.detail_meta.setWordWrap(True)
        rv.addWidget(self.detail_meta)
        self.manual_banner=QLabel('① 연결 → ② 보내기 전 편집 ON → ③ 앱에서 작업 → ④ Raw 수정 후 전송')
        self.manual_banner.setObjectName('manualBanner')
        self.manual_banner.setWordWrap(True)
        rv.addWidget(self.manual_banner)
        replace_row = QHBoxLayout()
        self.find_text = QLineEdit()
        self.find_text.setPlaceholderText('찾을 문자열 (예: user01)')
        self.replace_text = QLineEdit()
        self.replace_text.setPlaceholderText('바꿀 문자열 (예: user002)')
        self.replace_all = QCheckBox('전체 일치')
        replace_row.addWidget(self.find_text,1)
        replace_row.addWidget(self.replace_text,1)
        replace_row.addWidget(self.replace_all)
        replace_row.addWidget(button('치환', self.replace_current))
        replace_row.addWidget(button('규칙 저장', self.add_text_rule))
        self.inline_replace = QWidget()
        self.inline_replace.setLayout(replace_row)
        rv.addWidget(self.inline_replace)
        self.inline_replace.hide()
        self.tabs = QTabWidget()
        self.original_text, self.edited_text = self.editor_tab('Raw / 원문')
        self.original_hex, self.edited_hex = self.editor_tab('Hex')
        self.original_hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        fields_tab = QWidget()
        fl = QVBoxLayout(fields_tab)
        self.schema_label = QLabel('필드 정의가 없습니다. 실제 전송 명세의 offset/length를 입력하세요.')
        self.schema_label.setWordWrap(True)
        fl.addWidget(self.schema_label)
        self.field_table = QTableWidget(0, 5)
        self.field_table.setHorizontalHeaderLabels(['필드', '오프셋', '길이', '원본', '수정 값'])
        self.field_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.field_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.field_table.verticalHeader().hide()
        self.field_table.cellChanged.connect(self.field_changed)
        self.field_table.cellClicked.connect(self.field_clicked)
        fl.addWidget(self.field_table)
        field_hint = QLabel('수정 값 셀을 더블클릭해 편집 · 짧은 text 값은 정의된 pad로 채움 · 필드명 클릭 시 Hex 범위 강조')
        field_hint.setWordWrap(True)
        field_hint.setObjectName('hint')
        fl.addWidget(field_hint)
        self.tabs.addTab(fields_tab, '필드 편집')
        diff_tab = QWidget()
        dl = QVBoxLayout(diff_tab)
        self.diff_label = QLabel('변경 없음')
        dl.addWidget(self.diff_label)
        self.diff = QTableWidget(0, 3)
        self.diff.setHorizontalHeaderLabels(['오프셋', '원본 Hex', '수정 Hex'])
        self.diff.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.diff.verticalHeader().hide()
        dl.addWidget(self.diff)
        self.tabs.addTab(diff_tab, '변경 비교')
        self.tabs.currentChanged.connect(lambda _: self.render_aux())
        rv.addWidget(self.tabs, 1)
        self.validation = QLabel('')
        self.validation.setWordWrap(True)
        rv.addWidget(self.validation)
        actions = QHBoxLayout()
        actions.addWidget(button('원본 복원', self.reset_draft))
        self.final_button = button('적용본 불러오기', self.load_final)
        actions.addWidget(self.final_button)
        actions.addStretch()
        self.pass_button = button('원본으로 진행', lambda: self.proceed(False))
        self.apply_button = button('다음 요청 잡기', self.primary_action, True)
        actions.addWidget(self.pass_button)
        actions.addWidget(self.apply_button)
        rv.addLayout(actions)
        splitter.addWidget(right)
        splitter.setSizes([430, 1240])
        layout.addWidget(splitter, 1)
        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setMaximumBlockCount(150)
        self.logs.setMaximumHeight(88)
        self.logs.setPlaceholderText('연결 상태와 후크 설치 결과가 여기에 표시됩니다.')
        layout.addWidget(self.logs)
        self.statusBar().showMessage('DEMO · 전송 없이 편집 흐름을 시험할 수 있습니다.')
        for checkbox in (self.intercept, self.tx, self.rx, self.auto_rules, self.allow_resize, self.compatibility,self.capture_enabled):
            checkbox.toggled.connect(self.configure)
        self.break_filter.textChanged.connect(self.configure)
        self.timeout.valueChanged.connect(self.configure)
        self.source.currentIndexChanged.connect(self.configure)
        self.diagnostic.currentIndexChanged.connect(self.configure)
        self.edited_text.textChanged.connect(lambda: self.editor_changed('text'))
        self.edited_hex.textChanged.connect(lambda: self.editor_changed('hex'))
        self.update_stats()

    def editor_tab(self, name):
        tab = QWidget()
        box = QVBoxLayout(tab)
        if name.startswith('Raw'):
            split = QSplitter(Qt.Orientation.Horizontal)
            data_area = QWidget()
            data_area.setMinimumHeight(100)
            data_layout = QVBoxLayout(data_area)
            data_layout.setContentsMargins(0,0,0,0)
            self.raw_title = QLabel('전달 데이터 · 읽기 전용')
            data_layout.addWidget(self.raw_title)
            original = QPlainTextEdit(tab)
            original.hide()
            editor = QPlainTextEdit()
            editor.setFont(MONO)
            editor.setReadOnly(True)
            data_layout.addWidget(editor)
            split.addWidget(data_area)
            self.inline_rules = RulesDialog(self.rules, self, embedded=True)
            self.inline_rules.accepted.connect(lambda: self.apply_rule_list(self.inline_rules.result_value))
            self.inline_rules.deleted.connect(lambda rules: self.apply_rule_list(rules, activate=False))
            split.addWidget(self.inline_rules)
            split.setChildrenCollapsible(False)
            split.setSizes([560,560])
            box.addWidget(split)
            self.tabs.addTab(tab,name)
            return original,editor
        split = QSplitter(Qt.Orientation.Horizontal)
        editors = []
        for title in ('원본 · 보존', '보낼 데이터 · 직접 편집'):
            area = QWidget()
            inner = QVBoxLayout(area)
            inner.setContentsMargins(0, 0, 0, 0)
            inner.addWidget(QLabel(title))
            editor = QPlainTextEdit()
            editor.setFont(MONO)
            editor.setReadOnly(not editors)
            inner.addWidget(editor)
            editors.append(editor)
            split.addWidget(area)
        box.addWidget(split)
        hint = QLabel('제어바이트 \\x00 · 역슬래시 \\\\ · CR \\r · 대기 패킷은 오른쪽을 직접 수정한 뒤 전송하세요.' if name.startswith('Raw') else '수정본에는 Hex 바이트만 입력하세요. 오프셋과 ASCII 열은 원본에만 표시합니다.')
        hint.setObjectName('hint')
        hint.setWordWrap(True)
        box.addWidget(hint)
        self.tabs.addTab(tab, name)
        return editors

    def configure(self, *_):
        if not hasattr(self, 'auto_rules'):
            return
        try:
            compiled = compile_rules(self.rules,self.encoding)
        except (ValueError,UnicodeError) as e:
            self.log('규칙 설정 실패: '+str(e))
            self.auto_rules.setChecked(False)
            compiled = []
        if not self.capture_enabled.isChecked():
            for control in (self.intercept,self.auto_rules):
                control.blockSignals(True)
                control.setChecked(False)
                control.blockSignals(False)
        self.capture_enabled.setText('캡처 ON' if self.capture_enabled.isChecked() else '캡처 OFF')
        settings = dict(intercept=self.intercept.isChecked(), rules=self.auto_rules.isChecked(),capture=self.capture_enabled.isChecked(),
                        tx=self.tx.isChecked(), rx=self.rx.isChecked(), filter=self.break_filter.text(),
                        timeout=self.timeout.value(), requestSource=self.source.currentData(),
                        allowResize=self.allow_resize.isChecked(), compiledRules=compiled, lengthFields=self.length_fields)
        settings['compatibility']=self.compatibility.isChecked()
        settings['profile']=self.profile.currentData()
        settings['diagnostic']=self.diagnostic.currentData()
        diagnostic = settings['profile']=='shinyoung' and settings['diagnostic']!='capture'
        if diagnostic:
            settings['rules']=settings['intercept']=False
            self.capture_enabled.setText('진단 · 캡처 없음')
        self.inline_rules.setEnabled(not diagnostic)
        self.backend.configure(settings)
        self.intercept.setText('보내기 전 편집 ON' if settings['intercept'] else '보내기 전 편집 OFF')
        if self.mode=='live':
            self.mode_label.setText('LIVE · 실시간 캡처 중' if settings['capture'] else 'LIVE · 캡처 중지')
            if settings['profile']=='shinyoung' and settings['diagnostic']!='capture':
                self.mode_label.setText('LIVE · 연결 진단 중 · 캡처 없음')
        if not settings['intercept'] and not settings['rules']:
            self.release_all()
        self.update_stats()

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.Type.ShortcutOverride, QEvent.Type.KeyPress):
            if isinstance(watched,QWidget) and watched.window() is self and Qt.Key.Key_1 <= event.key() <= Qt.Key.Key_5 and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if event.type() == QEvent.Type.KeyPress and not event.isAutoRepeat():
                    self.mark_current(event.key() - Qt.Key.Key_0)
                event.accept()
                return True
            if isinstance(watched,QWidget) and watched.window() is self and event.key() == Qt.Key.Key_X and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if event.type() == QEvent.Type.KeyPress:
                    self.clear_packets()
                event.accept()
                return True
            if isinstance(watched,QWidget) and watched.window() is self and event.key() in (Qt.Key.Key_Up,Qt.Key.Key_Down):
                focus=QApplication.focusWidget()
                editing=isinstance(focus,(QLineEdit,QComboBox,QSpinBox)) or isinstance(focus,QPlainTextEdit) and not focus.isReadOnly()
                editing=editing or focus is self.field_table or focus is self.diff
                modifiers=event.modifiers()
                if modifiers==Qt.KeyboardModifier.AltModifier or modifiers==Qt.KeyboardModifier.NoModifier and not editing:
                    if event.type()==QEvent.Type.KeyPress:
                        self.navigate_packet(-1 if event.key()==Qt.Key.Key_Up else 1)
                    event.accept()
                    return True
        return super().eventFilter(watched,event)

    def mark_current(self, marker):
        p = self.current
        if p is None:
            self.statusBar().showMessage('색상을 지정할 패킷을 먼저 선택하세요.',3000)
            return
        p.marker = 0 if p.marker == marker else marker
        self.update_row(p)
        self.session_dirty = True
        self.statusBar().showMessage(f'패킷 색상: {MARKERS[p.marker][1]} · 세션 저장 시 함께 보관됩니다.',5000)

    def toggle_advanced(self):
        self.advanced_panel.setVisible(not self.advanced_panel.isVisible())

    def navigate_packet(self, step):
        visible=[row for row in range(self.table.rowCount()) if not self.table.isRowHidden(row)]
        if not visible:
            return
        focus=QApplication.focusWidget()
        if focus and self.field_table.isAncestorOf(focus):
            self.table.setFocus()
        row=self.table.currentRow()
        if step>0:
            target=next((candidate for candidate in visible if candidate>row),visible[-1])
        else:
            target=next((candidate for candidate in reversed(visible) if candidate<row),visible[0]) if row>=0 else visible[-1]
        self.table.setCurrentCell(target,0)
        self.table.selectRow(target)
        self.table.scrollToItem(self.table.item(target,0))

    def show_pending(self):
        p=next((p for p in self.packets if p.pending and p.status!='후크 확인 대기'),None)
        if p:
            self.table.setRowHidden(self.packets.index(p),False)
            self.table.setCurrentCell(self.packets.index(p),0)
            self.table.selectRow(self.packets.index(p))
            self.table.scrollToItem(self.table.item(self.packets.index(p),0))
            self.tabs.setCurrentIndex(0)
            self.edited_text.setFocus()

    def primary_action(self):
        if self.current and self.current.pending:
            self.proceed(True)
        elif any(p.pending for p in self.packets):
            self.show_pending()
        else:
            self.arm_manual()

    def arm_manual(self):
        if self.profile.currentData() == 'shinyoung':
            self.log('신영 어댑터는 캡처·자동 치환용입니다. 간편 치환 규칙에서 설정하세요.')
            return
        self.capture_enabled.setChecked(True)
        self.tx.setChecked(True)
        self.rx.setChecked(False)
        self.auto_rules.setChecked(False)
        packet_threads=self.backend.thread_stats.get('packet',{})
        crypto_threads=self.backend.thread_stats.get('encrypt',{})
        if self.source.currentData()=='packet' and packet_threads.get('main') and not packet_threads.get('worker') and crypto_threads.get('worker'):
            self.source.setCurrentIndex(self.source.findData('encrypt'))
            self.log('수동 편집 지점을 작업 스레드의 암호화 전 본문으로 선택했습니다. 이 지점은 본문만 수정합니다.')
        self.intercept.setChecked(True)
        if self.mode=='demo':
            self.backend.demo(direction='TX')
        else:
            self.statusBar().showMessage('편집할 요청을 기다립니다. 휴대폰에서 작업을 실행하세요.',10000)
        self.update_stats()

    def clear_packets(self):
        self.backend.release_all()
        self.backend.clear_display()
        self.current = None
        self.packets.clear()
        self.by_id.clear()
        self.recent_packets.clear()
        self.capture_sequence = 0
        self.table.setRowCount(0)
        self.updating = True
        for editor in (self.original_text,self.edited_text,self.original_hex,self.edited_hex):
            editor.clear()
        self.field_table.setRowCount(0)
        self.diff.setRowCount(0)
        self.updating = False
        self.detail_title.setText('패킷을 선택하세요')
        self.detail_meta.clear()
        self.validation.clear()
        self.diff_label.setText('변경 없음')
        self.session_dirty = False
        self.update_stats()
        self.log('목록 비움 · 대기 중 패킷은 원본 진행 · 새 캡처는 계속합니다.')

    def flush_display(self):
        events = self.backend.drain_display()
        if not events:
            return
        self.batch = True
        self.table.setUpdatesEnabled(False)
        try:
            for kind,meta,data in events:
                {'packet':self.receive,'prepared':self.prepared,'settled':self.settled}[kind](meta,data)
        finally:
            self.batch = False
            self.table.setUpdatesEnabled(True)
        self.filter_rows()
        self.update_stats()

    def prepared(self, meta, data):
        p = self.by_id.get(meta.get('id'))
        if p:
            p.draft = data
            p.note = ', '.join(meta.get('names',[]))
            if p is self.current:
                self.render_editors()
                self.render_aux()
                self.update_stats()

    def replace_current(self):
        p = self.current
        if p is None:
            return
        try:
            raw,count = replace_bytes(p.draft,self.find_text.text().encode(self.encoding),self.replace_text.text().encode(self.encoding),self.replace_all.isChecked(),self.allow_resize.isChecked())
            if not count:
                self.statusBar().showMessage('찾을 문자열이 현재 수정본에 없습니다.',5000)
                return
            self.set_draft(raw)
            self.statusBar().showMessage(f'{count}곳 치환 · {len(p.original)} B → {len(p.draft)} B',8000)
        except (ValueError,UnicodeError,OverflowError) as e:
            self.statusBar().showMessage('치환 실패: '+str(e),10000)

    def set_draft(self, data):
        p = self.current
        if p is None:
            return
        if self.allow_resize.isChecked():
            data = update_lengths(data,self.length_fields,p.direction,p.stage)
        p.draft = data
        p.error = ''
        p.invalid_text = p.invalid_hex = None
        if p.origin != 'demo':
            self.session_dirty = True
        self.render_editors()
        self.render_aux()
        self.update_stats()

    def add_text_rule(self):
        try:
            rule = dict(name=self.find_text.text()+' → '+self.replace_text.text(),kind='text',
                        find_text=self.find_text.text(),replace_text=self.replace_text.text(),encoding=self.encoding,
                        direction=self.current.direction if self.current else 'ANY',contains=self.break_filter.text(),
                        enabled=True,all=self.replace_all.isChecked(),allow_resize=self.allow_resize.isChecked())
            rules = validate_rules({'rules':self.rules+[rule]})
            compile_rules(rules,self.encoding)
            self.rules = rules
            self.refresh_rule_count()
            self.log('문자열 규칙 저장. 「자동 치환」을 체크하면 이후 패킷에 적용합니다.')
        except (ValueError,UnicodeError) as e:
            self.log('규칙 저장 실패: '+str(e))

    def refresh_rule_count(self):
        count = sum(r['enabled'] for r in self.rules)
        self.auto_rules.setText(f'자동 치환 ({count})')
        self.auto_rules.setEnabled(bool(count))
        if not count:
            self.auto_rules.setChecked(False)
        self.configure()

    def edit_length_fields(self):
        dialog = JsonDialog('길이 정보 · 전체 바이트 수 + adjust · 명세가 확인된 고정 헤더 위치만 입력',{'length_fields':self.length_fields},validate_lengths,self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.length_fields = dialog.result_value
            self.configure()

    def log(self, text):
        text=str(text)[:3000]
        LOGGER.info(text)
        self.logs.appendPlainText(datetime.now().strftime('%H:%M:%S') + '  ' + text)

    def add_demo(self):
        if self.mode in ('live', 'connecting'):
            self.statusBar().showMessage('실제 기기 연결을 해제한 뒤 데모를 추가하세요.', 5000)
            return
        self.mode = 'demo'
        self.mode_label.setText('DEMO · 실제 통신 없음')
        self.backend.mode = 'demo'
        self.backend.demo()

    def list_apps(self):
        self.list_apps_button.setEnabled(False)
        self.backend.list_applications(self.address.currentText())
        self.log('앱 목록 조회 중…')

    def apps_loaded(self, apps):
        self.list_apps_button.setEnabled(True)
        old = self.target.currentText()
        self.target.clear()
        for identifier, name, pid in sorted(apps, key=lambda a: (not bool(a[2]), a[1])):
            self.target.addItem(identifier, dict(name=name, pid=pid))
            self.target.setItemData(self.target.count()-1, f'{name} · PID {pid or "실행 안 됨"}', Qt.ItemDataRole.ToolTipRole)
        if old:
            self.target.setEditText(old)
        self.log(f'앱 목록 {len(apps)}개')

    def connect_live(self):
        target = self.target.currentText().strip()
        if not target:
            self.target.setFocus()
            self.log('연결할 앱 패키지명, 프로세스명 또는 PID를 입력하세요.')
            return
        expected = 'com.shinyoung.mts' if self.profile.currentData() == 'shinyoung' else 'kr.com.wink'
        if not target.isdecimal() and target != expected:
            self.log(f'선택한 대상 앱과 패키지가 다릅니다. {expected}를 사용하거나 대상 앱 선택을 바꾸세요.')
            return
        self.backend.release_all()
        self.log('단일 후크 모드: 같은 앱의 기존 frida -l android.js 연결은 종료한 상태에서 사용하세요.')
        self.configure()
        agent = 'agent-shinyoung.js' if self.profile.currentData() == 'shinyoung' else 'agent.js'
        self.backend.connect_device(self.address.currentText(), target, self.spawn.isChecked(), ASSETS / agent)

    def connect_recommended(self):
        target=self.target.currentText().strip()
        if not target or target.isdecimal():
            self.log('조회 시작에는 앱 패키지명을 입력하세요. PID 연결은 버튼 오른쪽 메뉴의 일반 연결을 사용합니다.')
            self.target.setFocus()
            return
        shinyoung = self.profile.currentData() == 'shinyoung'
        self.compatibility.setChecked(not shinyoung)
        self.spawn.setChecked(not shinyoung)
        self.capture_enabled.setChecked(True)
        self.intercept.setChecked(False)
        self.auto_rules.setChecked(False)
        self.log('신영: 휴대폰에서 실행한 앱에 연결 · 교보 사전 설정 미사용' if shinyoung else '교보 권장 조회 설정 적용: 사전 설정 ON · 시작하며 연결 ON · 가로채기 OFF · 자동 치환 OFF')
        self.connect_live()

    def disconnect_live(self):
        self.backend.disconnect()

    def connection_changed(self, mode):
        self.mode = mode
        self.mode_label.setText({'live':'LIVE · 실시간 캡처 중', 'connecting':'연결 중…', 'disconnected':'연결 안 됨 · 데모 사용 가능'}.get(mode, mode))
        connected = mode in ('live', 'connecting')
        self.diagnostic.setEnabled(not connected)
        if mode=='live' and self.profile.currentData()=='shinyoung' and self.diagnostic.currentData()!='capture':
            self.mode_label.setText('LIVE · 연결 진단 중 · 캡처 없음')
        self.profile.setEnabled(not connected)
        self.target.setEnabled(not connected)
        self.connect_button.setEnabled(not connected)
        self.disconnect_button.setEnabled(connected)
        self.demo_button.setEnabled(not connected)
        for control in (self.target, self.address, self.spawn):
            control.setEnabled(not connected)
        self.compatibility.setEnabled(not connected and self.profile.currentData() == 'kyobo')

    def change_profile(self):
        self.profile_state[self.active_profile] = (self.rules, self.fields, self.length_fields)
        self.active_profile = self.profile.currentData()
        self.rules, self.fields, self.length_fields = self.profile_state.get(self.active_profile, ([], [], []))
        shinyoung = self.active_profile == 'shinyoung'
        self.diagnostic.setVisible(shinyoung)
        self.diagnostic.setCurrentIndex(0)
        self.intercept.setChecked(False)
        self.auto_rules.setChecked(False)
        self.allow_resize.setChecked(False)
        self.compatibility.setChecked(False)
        self.compatibility.setEnabled(not shinyoung)
        self.intercept.setEnabled(not shinyoung)
        self.source.setEnabled(not shinyoung)
        self.spawn.setChecked(not shinyoung)
        self.target.setEditText('com.shinyoung.mts' if shinyoung else 'kr.com.wink')
        self.refresh_rule_count()
        self.configure()
        self.log('신영 선택 · 규칙 분리 · 캡처/자동 치환 어댑터는 실기기 확인이 필요합니다.' if shinyoung else '교보 선택 · 기존 후크와 이 앱의 규칙을 사용합니다.')
        self.inline_rules.populate(self.rules)
        self.inline_rules.error.clear()

    def receive(self, meta, data):
        key = (meta['direction'],meta['stage'],hash(data))
        previous = self.recent_packets.get(key)
        if self.group_repeats.isChecked() and not meta.get('pending') and not meta.get('autoChanged') and previous and previous.id in self.by_id and previous.original == data and 0 <= meta['timestamp']-previous.last_seen <= 1:
            previous.repeats += 1
            previous.last_seen = meta['timestamp']
            self.update_row(previous)
            return
        while len(self.packets) >= MAX_EVENTS or (sum(len(p.original) + len(p.draft) for p in self.packets) + len(data)*2 > 32*1024*1024):
            index = next((i for i,p in enumerate(self.packets) if not p.pending and p is not self.current), None)
            if index is None:
                if meta.get('pending'):
                    self.backend.decide(meta['id'], 'original')
                self.log('보관 한도에 도달해 이벤트를 건너뛰었습니다. 대기 중 데이터는 원본 진행합니다.')
                return
            old = self.packets.pop(index)
            self.by_id.pop(old.id, None)
            old_key=(old.direction,old.stage,hash(old.original))
            if self.recent_packets.get(old_key) is old:
                self.recent_packets.pop(old_key,None)
            self.table.removeRow(index)
        p = Packet(meta['id'], meta['direction'], meta['stage'], meta['timestamp'], data,
                   origin='demo' if meta.get('demo') else 'live', pending=bool(meta.get('pending')),
                   status='대기' if meta.get('pending') else '캡처', deadline=meta.get('deadline', 0), demo_profile=bool(meta.get('demo')))
        p.main_thread=meta.get('mainThread') if type(meta.get('mainThread')) is bool else None
        p.thread_id=meta.get('thread')
        if meta.get('overflow'):
            p.status = '대기 초과 원본'
        elif meta.get('mainThread') and meta.get('manual'):
            p.status = '메인 스레드 · 조회'
        p.note = ', '.join(meta.get('autoNames',[])) or meta.get('ruleError','')
        self.capture_sequence += 1
        p.sequence = self.capture_sequence
        self.packets.append(p)
        self.by_id[p.id] = p
        self.recent_packets[key] = p
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.update_row(p)
        if p.origin == 'live':
            self.session_dirty = True
        if p.pending and p.origin == 'demo' and self.auto_rules.isChecked():
            try:
                p.draft, names = apply_rules(p.original, p.direction, self.rules, self.encoding,self.allow_resize.isChecked())
                if self.allow_resize.isChecked():
                    p.draft = update_lengths(p.draft,self.length_fields,p.direction,p.stage)
                p.note = ', '.join(names)
            except Exception as e:
                self.log(f'치환 오류 · 원본 유지: {e}')
        if p.pending and p.origin == 'demo' and not meta.get('manual'):
            self.backend.decide(p.id, 'replace' if p.draft != p.original else 'original', p.draft if p.draft != p.original else None)
        if self.current is None or (p.pending and not self.current.pending):
            self.table.selectRow(row)
        if not self.batch:
            self.filter_rows()
            self.tick()

    def settled(self, meta, data):
        p = self.by_id.get(meta.get('id'))
        if p is None:
            return
        p.pending = False
        p.final = None if meta.get('action') == 'cancelled' else data
        action = meta.get('action')
        p.status = {'replace':'수정 적용' if data != p.original else '원본 진행', 'original':'원본 진행',
                    'timeout':'만료 · 원본', 'cancelled':'연결 종료', 'rejected':'수정 거절 · 원본'}.get(action, '원본 진행')
        if meta.get('error'):
            p.note = str(meta['error'])
            self.log(f'{p.id}: {p.note}')
        if p.origin == 'demo':
            p.status = '데모 · ' + p.status
        self.update_row(p)
        if p.origin != 'demo':
            self.session_dirty = True
        if p is self.current:
            self.render_editors()
            self.render_aux()
            self.update_stats()
        if not self.batch:
            self.filter_rows()

    def update_row(self, p):
        row = self.packets.index(p)
        values = [str(p.sequence or row+1)+(f' ×{p.repeats}' if p.repeats>1 else ''), datetime.fromtimestamp(p.timestamp).strftime('%H:%M:%S.%f')[:-3],
                  '↑ 요청' if p.direction == 'TX' else '↓ 응답', transaction(p.original), f'{len(p.original):,} B', p.stage, p.status]
        for col, value in enumerate(values):
            item = self.table.item(row,col)
            if item is None:
                item = readonly_item(value)
                item.setData(Qt.ItemDataRole.UserRole,p.id)
                self.table.setItem(row,col,item)
            else:
                item.setText(str(value))
            item.setBackground(QBrush(QColor(MARKERS[p.marker][0])) if p.marker else QBrush())
            item.setToolTip(f'패킷 색상: {MARKERS[p.marker][1]} · Ctrl+1~5로 지정/해제')
            if col == 0:
                icon = QIcon()
                if p.marker:
                    swatch = QPixmap(12,12)
                    swatch.fill(QColor(MARKERS[p.marker][0]).darker(125))
                    icon = QIcon(swatch)
                item.setIcon(icon)
            if col == 2:
                item.setForeground(QColor('#167044' if p.direction == 'TX' else '#1f5fae'))
            if col == 6 and p.pending:
                item.setForeground(QColor('#9c5f12'))

    def select_packet(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        item = self.table.item(rows[0].row(), 0)
        if item:
            self.current = self.by_id.get(item.data(Qt.ItemDataRole.UserRole))
            self.render_editors()
            self.render_aux()
            self.update_stats()

    def render_editors(self, except_view=None):
        p = self.current
        if p is None:
            return
        self.updating = True
        try:
            direction = '요청' if p.direction == 'TX' else '응답'
            ink, background, border = ('#167044','#effaf3','#b8dfc6') if p.direction == 'TX' else ('#1f5fae','#eef5ff','#bdd4f3')
            for editor in (self.original_text,self.edited_text,self.original_hex,self.edited_hex):
                editor.setStyleSheet(f'QPlainTextEdit, QPlainTextEdit[readOnly="true"] {{color:{ink};background:{background};border:1px solid {border};}}')
            self.raw_title.setStyleSheet(f'color:{ink};font-weight:600;')
            large = len(p.original) > EDIT_LIMIT
            original = p.original[:4096] if large else p.original
            actual = p.draft if p.pending else (p.final if p.final is not None else p.original)
            draft = actual[:4096] if large else actual
            self.raw_title.setText(direction + ' 데이터 · ' + ('전송 전 대기 · 직접 편집' if p.pending else ('치환 적용 결과' if p.final is not None and p.final != p.original else '치환 미적용 / 원본')))
            self.inline_replace.setVisible(p.pending)
            self.original_text.setPlainText(visible(original, self.encoding))
            self.original_hex.setPlainText(hexdump(original))
            if except_view != 'text':
                self.edited_text.setPlainText(p.invalid_text if p.invalid_text is not None else visible(draft, self.encoding))
            if except_view != 'hex':
                self.edited_hex.setPlainText(p.invalid_hex if p.invalid_hex is not None else '\n'.join(draft[i:i+16].hex(' ') for i in range(0, len(draft), 16)))
            self.edited_text.setReadOnly(large or not p.pending)
            self.edited_hex.setReadOnly(large or not p.pending)
        finally:
            self.updating = False

    def editor_changed(self, view):
        if self.updating or not self.current:
            return
        p = self.current
        try:
            candidate = parse_visible(self.edited_text.toPlainText(), self.encoding) if view == 'text' else parse_hex(self.edited_hex.toPlainText())
            p.draft = update_lengths(candidate,self.length_fields,p.direction,p.stage) if self.allow_resize.isChecked() else candidate
            p.error = ''
            p.invalid_text = p.invalid_hex = None
            editor = self.edited_text if view == 'text' else self.edited_hex
            cursor = editor.textCursor()
            cursor_position = cursor.position()
            self.render_editors(except_view=view if candidate == p.draft else None)
            if candidate != p.draft:
                cursor = editor.textCursor()
                cursor.setPosition(min(cursor_position,len(editor.toPlainText())))
                editor.setTextCursor(cursor)
            self.render_aux()
            if p.origin != 'demo':
                self.session_dirty = True
        except (ValueError, UnicodeError, OverflowError) as e:
            p.error = str(e)
            if view == 'text':
                p.invalid_text = self.edited_text.toPlainText()
            else:
                p.invalid_hex = self.edited_hex.toPlainText()
        self.update_stats()

    def active_fields(self):
        if not self.current:
            return []
        return DEMO_FIELDS if self.current.demo_profile else self.fields

    def render_aux(self):
        if not self.current or not hasattr(self, 'field_table'):
            return
        p = self.current
        if self.tabs.currentIndex() == 2:
            self.updating = True
            fields = self.active_fields()
            self.schema_label.setText('DEMO 전용 필드 정의 · 실제 앱 명세와 무관합니다.' if p.demo_profile else ('사용자 정의 필드 · 오프셋은 이 수집 지점의 첫 바이트부터 계산합니다.' if fields else '필드 정의가 없습니다. 상단 「필드 정의」에서 실제 전송 명세를 입력하세요.'))
            self.field_table.setRowCount(len(fields))
            for row, f in enumerate(fields):
                try:
                    values = [f['name'], f['offset'], f['length'], field_value(p.original, f, self.encoding), field_value(p.draft, f, self.encoding)]
                    valid = len(p.original) <= EDIT_LIMIT
                except ValueError:
                    values = [f['name'], f['offset'], f['length'], '범위 초과', '범위 초과']
                    valid = False
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value)) if col == 4 and valid else readonly_item(value)
                    self.field_table.setItem(row, col, item)
            self.updating = False
        if self.tabs.currentIndex() == 3:
            changes = [i for i in range(max(len(p.original),len(p.draft))) if p.original[i:i+1] != p.draft[i:i+1]]
            self.diff_label.setText(f'변경 {len(changes):,} B · 원본 {len(p.original):,} B → 수정 {len(p.draft):,} B' + (' · 앞의 512건만 표시' if len(changes)>512 else ''))
            self.diff.setRowCount(min(len(changes), 512))
            for row, offset in enumerate(changes[:512]):
                for col, value in enumerate([f'{offset} / 0x{offset:08x}', p.original[offset:offset+1].hex() or '—', p.draft[offset:offset+1].hex() or '—']):
                    self.diff.setItem(row, col, readonly_item(value))

    def field_changed(self, row, col):
        if self.updating or col != 4 or not self.current:
            return
        try:
            p = self.current
            p.draft = edit_field(p.draft, self.active_fields()[row], self.field_table.item(row, col).text(), self.encoding)
            p.error = ''
            p.invalid_text = p.invalid_hex = None
            if p.origin != 'demo':
                self.session_dirty = True
            self.render_editors()
            self.render_aux()
            self.update_stats()
        except (ValueError, OverflowError, UnicodeError) as e:
            self.statusBar().showMessage('필드 수정 실패: ' + str(e), 10000)
            self.render_aux()

    def field_clicked(self, row, col):
        if col != 0 or not self.current:
            return
        f = self.active_fields()[row]
        if f['offset'] + f['length'] > len(self.current.draft) or len(self.current.draft) > EDIT_LIMIT:
            return
        self.tabs.setCurrentIndex(1)
        cursor = self.edited_hex.textCursor()
        cursor.setPosition(f['offset'] * 3)
        cursor.setPosition((f['offset'] + f['length']) * 3 - 1, QTextCursor.MoveMode.KeepAnchor)
        self.edited_hex.setTextCursor(cursor)
        self.edited_hex.setFocus()

    def update_stats(self):
        p = self.current
        pending = sum(item.pending for item in self.packets)
        repeats=sum(item.repeats-1 for item in self.packets)
        self.pending_button.setText(f'대기 패킷 보기 ({pending})')
        self.pending_button.setEnabled(bool(pending))
        self.count_label.setText(f'{len(self.packets):,}행 · 반복 {repeats:,}건 묶음 · 대기 {pending}건 · 과부하 생략 {self.backend.dropped:,}건 · 최대 {MAX_EVENTS}행')
        if not p:
            self.apply_button.setText('다음 요청 잡기')
            self.apply_button.setEnabled(self.mode in ('demo','live'))
            self.pass_button.setEnabled(False)
            self.final_button.setEnabled(False)
            self.manual_banner.setText('① 연결 → ② 다음 요청 잡기 → ③ 앱에서 작업 → ④ Raw를 직접 수정하고 전송')
            self.manual_banner.setStyleSheet('')
            return
        self.detail_title.setText(f'{transaction(p.original)}  ·  {"요청" if p.direction=="TX" else "응답"}')
        origin = {'demo':'가상 데이터', 'live':'실제 기기', 'import':'가져온 세션'}[p.origin]
        self.detail_meta.setText(f'{origin} · {p.id} · {p.stage} · {p.status}' + (f' · 규칙/메모: {p.note}' if p.note else ''))
        delta = len(p.draft) - len(p.original)
        changed = sum(a != b for a,b in zip(p.original,p.draft)) + abs(delta)
        left = max(0, int(p.deadline - time.monotonic()))
        message = f'원본 {len(p.original):,} B · 수정 {len(p.draft):,} B · 변경 {changed:,} B'
        problem = p.error
        if delta and not self.allow_resize.isChecked():
            problem = problem or f'길이가 {delta:+,} B 다릅니다. 원본과 같은 바이트 길이로 맞추세요.'
        elif delta:
            message += f' · 길이 {delta:+,} B (가변 허용)'
            if not self.length_fields:
                message += ' · 별도 길이 정보 자동 갱신 없음'
        if len(p.original) > EDIT_LIMIT or len(p.draft)>EDIT_LIMIT:
            problem = '64 KiB 초과 데이터는 앞의 4 KiB만 표시합니다. 원본 진행과 세션 저장을 사용할 수 있습니다.'
        if p.pending:
            message += f' · 남은 {left}초 (만료 시 원본)'
        else:
            message += ' · 처리 완료 · 규칙은 새 패킷부터 적용'
        self.validation.setText(message + ('\n' + problem if problem else ''))
        self.validation.setStyleSheet('color:#a33b24;' if problem else 'color:#52667e;')
        waiting_ack = p.status == '후크 확인 대기'
        if p.pending:
            self.apply_button.setText('수정본 보내기' if p.direction=='TX' else '수정본 앱에 전달')
            self.pass_button.setText('원본 보내기' if p.direction=='TX' else '원본 앱에 전달')
            self.manual_banner.setText(f'전송 전 대기 중 · {left}초 남음\n오른쪽 Raw/Hex를 직접 수정하고 「{self.apply_button.text()}」를 누르세요.'+ ('\n'+problem if problem else ''))
            self.manual_banner.setStyleSheet('background:#fff2d6;color:#704610;border-color:#e8c078;')
            self.apply_button.setEnabled(not waiting_ack and not problem)
        else:
            self.pass_button.setText('원본 보내기')
            self.apply_button.setText(f'대기 패킷 보기 ({pending})' if pending else '다음 요청 잡기')
            self.apply_button.setEnabled(bool(pending) or self.mode in ('demo','live'))
            reason='이 패킷은 이미 처리됐습니다. 편집 내용은 초안이며 소급 전송되지 않습니다.'
            if p.main_thread and p.status=='메인 스레드 · 조회':
                reason='메인 스레드에서 처리된 호출이라 앱 멈춤을 막기 위해 중단하지 않았습니다. 다른 수집 지점을 확인해야 합니다.'
            self.manual_banner.setText(reason+'\n'+('「대기 패킷 보기」로 중단된 요청을 선택하세요.' if pending else '「다음 요청 잡기」를 누르고 휴대폰에서 작업을 다시 실행하세요.'))
            self.manual_banner.setStyleSheet('')
        self.pass_button.setEnabled(p.pending and not waiting_ack)
        self.final_button.setEnabled(p.final is not None)
        self.final_button.setVisible(p.pending)
        if self.profile.currentData() == 'shinyoung' and not p.pending:
            self.apply_button.setText('간편 치환 규칙에서 설정')
            self.apply_button.setEnabled(False)
            self.manual_banner.setText('신영 · 캡처 / 자동 치환 모드 · 실기기 검증 전\n간편 치환 규칙에서 저장하면 이후 발생하는 패킷에 적용합니다. 이미 처리된 패킷을 재전송하지 않습니다.')
        self.apply_button.setVisible(p.pending or self.intercept.isChecked())
        self.pass_button.setVisible(p.pending)
        if not p.pending and not self.intercept.isChecked() and self.profile.currentData() != 'shinyoung':
            self.manual_banner.setText('왼쪽은 전달 데이터, 오른쪽은 치환 규칙입니다. 원본은 Hex에서 확인할 수 있습니다.\n오른쪽 규칙을 저장하면 이후 발생하는 패킷에 자동 적용합니다.')
        if self.profile.currentData()=='shinyoung' and self.diagnostic.currentData()!='capture':
            self.manual_banner.setText('신영 연결 진단 · 패킷 후크와 치환은 설치하지 않습니다.\n스크립트 로드 후 10초 유지 로그와 앱 종료 여부를 확인하세요.')

    def tick(self):
        self.update_stats()

    def proceed(self, edited):
        p = self.current
        if not p or not p.pending:
            return
        if edited and (p.error or (len(p.draft) != len(p.original) and not self.allow_resize.isChecked()) or max(len(p.original),len(p.draft)) > EDIT_LIMIT):
            return
        try:
            if edited and self.allow_resize.isChecked():
                self.set_draft(p.draft)
            accepted = self.backend.decide(p.id, 'replace' if edited else 'original', p.draft if edited else None)
            if accepted and p.pending:
                p.status = '후크 확인 대기'
                self.update_row(p)
                self.apply_button.setEnabled(False)
                self.pass_button.setEnabled(False)
            elif not accepted:
                self.statusBar().showMessage('이미 진행되었거나 대기 시간이 만료되었습니다.', 5000)
        except Exception as e:
            self.log('진행 실패: ' + str(e))

    def release_all(self):
        self.backend.release_all()

    def reset_draft(self):
        if self.current:
            if self.current.origin != 'demo':
                self.session_dirty = True
            self.current.draft = self.current.original
            self.current.error = ''
            self.current.invalid_text = self.current.invalid_hex = None
            self.render_editors()
            self.render_aux()
            self.update_stats()

    def load_final(self):
        if self.current and self.current.final is not None:
            if self.current.origin != 'demo':
                self.session_dirty = True
            self.current.draft = self.current.final
            self.current.error = ''
            self.current.invalid_text = self.current.invalid_hex = None
            self.render_editors()
            self.render_aux()
            self.update_stats()

    def change_encoding(self):
        if any(p.error for p in self.packets):
            self.encoding_select.blockSignals(True)
            self.encoding_select.setCurrentIndex(self.encoding_select.findData(self.encoding))
            self.encoding_select.blockSignals(False)
            self.statusBar().showMessage('잘못된 편집 값을 수정하거나 원본 복원한 뒤 인코딩을 변경하세요.', 8000)
            return
        self.encoding = self.encoding_select.currentData()
        self.configure()
        self.render_editors()
        self.render_aux()
        self.update_stats()

    def filter_rows(self):
        query = self.search.text().lower().strip()
        if not query and not self.filter_active:
            return
        self.filter_active=bool(query)
        for row,p in enumerate(self.packets):
            direction_label = '요청' if p.direction == 'TX' else '응답'
            haystack = f'{p.id} {p.stage} {p.status} {p.direction} {direction_label} {p.note} {p.original.decode(self.encoding, errors="replace")} {p.original.hex()} {p.original.hex(" ")}'.lower()
            self.table.setRowHidden(row, bool(query and query not in haystack and not p.pending))

    def edit_schema(self):
        dialog = JsonDialog('필드 정의 · offset/length는 바이트 단위', {'fields':self.fields}, validate_fields, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.fields = dialog.result_value
            self.render_aux()
            self.log(f'실제 패킷용 필드 정의 {len(self.fields)}개 적용. DEMO에는 별도 예시 명세를 사용합니다.')

    def edit_rules(self):
        direction = self.current.direction if self.current else 'RX'
        dialog = RulesDialog(self.rules, self, direction=direction)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.apply_rule_list(dialog.result_value)

    def apply_rule_list(self, rules, activate=True):
        self.rules = rules
        if activate:
            self.capture_enabled.setChecked(True)
            self.intercept.setChecked(False)
            self.allow_resize.setChecked(any(r['enabled'] and r['allow_resize'] for r in self.rules))
        self.refresh_rule_count()
        if activate:
            self.auto_rules.setChecked(any(r['enabled'] for r in self.rules))
        self.configure()
        self.inline_rules.populate(self.rules)
        self.inline_rules.error.setText('저장 완료 · 이후 패킷부터 적용' if self.auto_rules.isChecked() else '저장 완료 · 자동 치환 OFF')
        self.log('간편 규칙 저장 · 자동 치환 '+('ON' if self.auto_rules.isChecked() else 'OFF')+' · 이후 발생하는 패킷부터 적용합니다.')

    def save_session(self):
        if any(p.error for p in self.packets):
            self.log('저장 전에 잘못된 편집 값을 수정하거나 원본 복원하세요. 유효하지 않은 입력을 잃지 않도록 저장을 중단했습니다.')
            return False
        path, _ = QFileDialog.getSaveFileName(self, '세션 저장', f'socket-session-{datetime.now():%Y%m%d-%H%M%S}.json', 'Socket Inspector 세션 (*.json)')
        if not path:
            return False
        try:
            save_session(Path(path), self.packets)
            self.session_dirty = False
            self.log('세션 저장: ' + path)
            return True
        except Exception as e:
            self.log('세션 저장 실패: ' + str(e))
            return False

    def open_session(self):
        path, _ = QFileDialog.getOpenFileName(self, '세션 열기', '', 'Socket Inspector 세션 (*.json)')
        if not path:
            return
        try:
            packets = load_session(Path(path))
            if sum(len(p.original)+len(p.draft) for p in self.packets+packets) > 32*1024*1024 or len(self.packets)+len(packets)>MAX_EVENTS:
                raise ValueError('현재 목록과 합치면 보관 한도를 넘습니다. 새로 실행한 뒤 불러오세요.')
            for i,p in enumerate(packets):
                p.id = f'import-{time.time_ns()}-{i}'
                self.packets.append(p)
                self.by_id[p.id] = p
                self.table.insertRow(self.table.rowCount())
                self.update_row(p)
            if packets:
                self.table.selectRow(len(self.packets)-len(packets))
            self.filter_rows()
            self.update_stats()
            self.log(f'세션 {len(packets)}건 가져옴 · 원본/초안/적용본 보존 · 실제 재전송 없음')
        except Exception as e:
            self.log('세션 열기 실패: ' + str(e))

    def closeEvent(self, event):
        if self.session_dirty:
            choice = QMessageBox.question(self, '세션 저장', '저장하지 않은 세션이 있습니다. 저장하시겠습니까?', QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Save)
            if choice == QMessageBox.StandardButton.Cancel or (choice == QMessageBox.StandardButton.Save and not self.save_session()):
                event.ignore()
                return
        self.backend.disconnect()
        event.accept()


def main():
    try:
        folder=(Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent.parent)/'logs'
        folder.mkdir(exist_ok=True)
        handler=RotatingFileHandler(folder/'events.log',maxBytes=524288,backupCount=2,encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        LOGGER.addHandler(handler)
        LOGGER.setLevel(logging.INFO)
        def exception_hook(kind,value,trace):
            LOGGER.error('GUI exception',exc_info=(kind,value,trace))
            if sys.stderr is not None:
                sys.__excepthook__(kind,value,trace)
        sys.excepthook=exception_hook
    except OSError:
        pass
    application = QApplication(sys.argv)
    # The offscreen Qt platform has no system font discovery on Windows.
    if application.platformName() == 'offscreen':
        font_dir = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts'
        for font_file in ('segoeui.ttf', 'malgun.ttf', 'consola.ttf'):
            QFontDatabase.addApplicationFont(str(font_dir / font_file))
    application.setFont(QFont('Malgun Gothic', 10))
    application.setStyle('Fusion')
    window = Window()
    window.show()
    if '--smoke-test' in sys.argv:
        def smoke():
            try:
                assert not window.intercept.isChecked()
                window.intercept.setChecked(True)
                window.add_demo()
                window.table.selectRow(window.table.rowCount()-1)
                p = window.current
                assert p is not None and p.pending
                window.edited_text.setPlainText(visible(p.original).replace('0001250000', '0002250000'))
                assert p.draft != p.original and len(p.draft) == len(p.original)
                window.proceed(True)
                assert p.final == p.draft and not p.pending
                window.add_demo()
                window.table.selectRow(window.table.rowCount()-1)
                window.tabs.setCurrentIndex(2)
                window.field_table.item(2,4).setText('0001')
                assert window.current.draft[15:19] == b'0001'
                window.tabs.setCurrentIndex(3)
                assert window.diff.rowCount() == 1
                window.backend.release_all()
                # The requested Ctrl+X must clear the list even when an editor has focus.
                override=QKeyEvent(QEvent.Type.ShortcutOverride,Qt.Key.Key_X,Qt.KeyboardModifier.ControlModifier)
                press=QKeyEvent(QEvent.Type.KeyPress,Qt.Key.Key_X,Qt.KeyboardModifier.ControlModifier)
                assert window.eventFilter(window.edited_text,override)
                assert window.eventFilter(window.edited_text,press)
                assert not window.packets and window.table.rowCount()==0 and window.current is None
                window.backend._register(dict(id='demo-resize',direction='TX',stage='DEMO / variable',timestamp=time.time(),demo=True,pending=True,manual=True,timeout=15),b'user=user01|mode=demo')
                p=window.current
                window.allow_resize.setChecked(True)
                window.find_text.setText('user01')
                window.replace_text.setText('user002')
                window.replace_current()
                assert p.draft==b'user=user002|mode=demo'
                assert len(p.draft)==len(p.original)+1 and window.apply_button.isEnabled()
                window.proceed(True)
                assert p.final==b'user=user002|mode=demo'
                window.clear_packets()
                sample=dict(direction='RX',stage='LOAD TEST',timestamp=time.time(),pending=False)
                for i in range(5000):
                    window.receive(dict(sample,id=f'load-{i}'),b'repeated')
                assert len(window.packets)==1 and window.packets[0].repeats==5000
                window.clear_packets()
                window.group_repeats.setChecked(False)
                window.batch=True
                window.table.setUpdatesEnabled(False)
                for i in range(1500):
                    window.receive(dict(sample,id=f'unique-{i}'),f'packet-{i}'.encode())
                window.batch=False
                window.table.setUpdatesEnabled(True)
                assert len(window.packets)==MAX_EVENTS and window.table.rowCount()==MAX_EVENTS
                window.clear_packets()
                window.group_repeats.setChecked(True)
                window.intercept.setChecked(False)
                window.backend._register(dict(id='demo-resize-preview',direction='TX',stage='DEMO / variable',timestamp=time.time(),demo=True,pending=False,manual=False,timeout=15),b'user=user01|mode=demo')
                window.replace_current()
                window.tabs.setCurrentIndex(0)
                destination = next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--screenshot=')), '')
                if destination:
                    assert window.grab().save(destination)
                report = next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--test-report=')), '')
                if report:
                    Path(report).write_text('GUI SMOKE PASS: fixed/variable editing, field edit, Ctrl+X, default observe, 5000 repeated packets grouped.', encoding='utf-8')
                if sys.stdout is not None:
                    print('GUI SMOKE PASS: fixed/variable editing, field edit, Ctrl+X, default observe, 5000 repeated packets grouped.', flush=True)
                application.exit(0)
            except Exception:
                import traceback
                report = next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--test-report=')), '')
                if report:
                    Path(report).write_text(traceback.format_exc(), encoding='utf-8')
                if sys.stderr is not None:
                    traceback.print_exc()
                application.exit(1)
        QTimer.singleShot(200, smoke)
    sys.exit(application.exec())


if __name__ == '__main__':
    main()
