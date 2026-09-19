# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IHttpRequestResponse, IHttpListener
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, BoxLayout,
    JOptionPane, JMenuItem, JTextField, DefaultCellEditor,
    SwingUtilities, JSplitPane, JTabbedPane, BorderFactory,
    JPopupMenu, JSpinner, SpinnerNumberModel, JColorChooser,
    JCheckBox, UIManager, ListSelectionModel, JComboBox,
    RowFilter, DefaultComboBoxModel, JTextArea, JDialog, JFileChooser
)
from javax.swing.table import DefaultTableModel, TableCellRenderer, TableRowSorter
from javax.swing.border import EmptyBorder, LineBorder
from javax.swing.event import DocumentListener
from java.awt import (
    BorderLayout, Dimension, Color, Font, GridBagLayout,
    GridBagConstraints, Insets, FlowLayout, Component
)
from java.awt.event import MouseAdapter, MouseEvent, ActionListener
from java.lang import String, Thread, Runnable
from java.util import TimeZone, Date
from java.util.concurrent import LinkedBlockingQueue
from java.text import SimpleDateFormat
from java.io import File
import json
import re
import base64
import os
import tempfile
import threading

SAVE_FILE     = os.path.join(tempfile.gettempdir(), "pr0f_headerswitch_results.json")
SETTINGS_FILE = os.path.join(tempfile.gettempdir(), "pr0f_headerswitch_settings.json")
HISTORY_FILE  = os.path.join(tempfile.gettempdir(), "pr0f_headerswitch_history.json")
GREP_FILE     = os.path.join(tempfile.gettempdir(), "pr0f_headerswitch_grep.json")
DEFAULT_FONT_SIZE = 15
CONTAINER_HEADER_NAME = "X-PR0F-Container"

DEFAULT_COLORS = [
    "#E74C3C", "#E67E22", "#F1C40F", "#2ECC71", "#1ABC9C",
    "#3498DB", "#9B59B6", "#E91E63", "#00BCD4", "#8BC34A",
    "#FF5722", "#607D8B", "#795548", "#9E9E9E", "#FF9800"
]

REPLACE_TYPES = ["Header", "Parameter"]

ALL_RESULT_COLUMNS     = ["ID", "Role", "Status", "Size", "Time", "Host", "Method", "URL", "Params", "Match"]
DEFAULT_VISIBLE_COLUMNS = ["ID", "Role", "Status", "Size"]


def hex_to_color(h):
    h = h.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return Color(r, g, b)


def color_to_hex(c):
    return "#%02X%02X%02X" % (c.getRed(), c.getGreen(), c.getBlue())


def cairo_timestamp():
    sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    sdf.setTimeZone(TimeZone.getTimeZone("Africa/Cairo"))
    return sdf.format(Date())


def _norm_container_name(s):
    """Single normalization point for container-name matching. Matching is
    ALWAYS exact equality on the normalized (trimmed, lower-cased) string -
    never a prefix/substring/startswith check - so containers with similar
    names (e.g. 'victim' and 'victim2') can never be confused with each
    other, in either direction."""
    return (s or u"").strip().lower()


def _u(v):
    if v is None:
        return u""
    if isinstance(v, unicode):
        return v
    try:
        return unicode(v, "utf-8")
    except:
        return unicode(v)


def _regex_escape_flex(s):
    """re.escape() a string but collapse any run of whitespace into \\s+, so
    the fingerprint still matches if line-wrapping/indentation shifts a bit
    between captures - the literal characters otherwise stay pinned exactly
    as highlighted."""
    parts = re.split(r'(\s+)', s)
    out = []
    for p in parts:
        if p == "":
            continue
        if re.match(r'^\s+$', p):
            out.append(r'\s+')
        else:
            out.append(re.escape(p))
    return u"".join(out)


def _build_fingerprint_regex(prefix, suffix):
    """Builds a 'Grep Extract' style regex: fixed prefix ... (captured value,
    non-greedy) ... fixed suffix. Mirrors Burp Intruder's own Grep Extract
    payload processing rule."""
    return _regex_escape_flex(prefix) + r'(.*?)' + _regex_escape_flex(suffix)


class BgThread(Thread):
    def __init__(self, fn):
        self.fn = fn
    def run(self):
        try:
            self.fn()
        except Exception as e:
            print("[BgThread Error] " + str(e))

class JobQueueWorker(Thread):
    def __init__(self, queue):
        self._queue = queue
        self._stop = False
    def run(self):
        while not self._stop:
            try:
                job = self._queue.take()
            except Exception:
                continue
            if job is None:
                continue
            try:
                job.run() if hasattr(job, "run") else job()
            except Exception as e:
                print("[Queue Job Error] " + str(e))
    def stop(self):
        self._stop = True
        self._queue.put(None)

class HistoryMsgWrapper(IHttpRequestResponse):
    def __init__(self, request, service):
        self._request   = request
        self._response  = None
        self._service   = service
        self._comment   = None
        self._highlight = None
    def getRequest(self):
        return self._request
    def setRequest(self, req):
        self._request = req
    def getResponse(self):
        return self._response
    def setResponse(self, resp):
        self._response = resp
    def getHttpService(self):
        return self._service
    def setHttpService(self, service):
        self._service = service
    def getComment(self):
        return self._comment
    def setComment(self, comment):
        self._comment = comment
    def getHighlight(self):
        return self._highlight
    def setHighlight(self, color):
        self._highlight = color


class ColoredRowRenderer(TableCellRenderer):
    def __init__(self, colors_map_fn, base_font_size):
        self._get_colors_map = colors_map_fn
        self._fsz = base_font_size
        self._lbl = JLabel()
        self._lbl.setOpaque(True)
        self._lbl.setFont(Font("Monospaced", Font.BOLD, base_font_size))

    @staticmethod
    def _contrast_fg(bg):
        lum = bg.getRed() * 0.299 + bg.getGreen() * 0.587 + bg.getBlue() * 0.114
        if lum < 100:
            return Color(255, 230, 100)
        elif lum < 160:
            return Color(255, 255, 200)
        else:
            return Color(20, 20, 20)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        self._lbl.setText(_u(value))
        model = table.getModel()
        try:
            role_col = model.findColumn("Role")
            raw_role = model.getValueAt(row, role_col)
        except:
            raw_role = None
        role_name = _u(raw_role)

        self._lbl.setFont(Font("Monospaced", Font.BOLD, self._fsz))
        colors_map = self._get_colors_map()
        bg = Color(38, 38, 38)
        hexv = colors_map.get(role_name)
        if hexv:
            try:
                base = hex_to_color(hexv)
                bg = Color(
                    max(0, base.getRed()   - 55),
                    max(0, base.getGreen() - 55),
                    max(0, base.getBlue()  - 55)
                )
            except:
                pass

        fg = ColoredRowRenderer._contrast_fg(bg)
        if isSelected:
            bg = bg.brighter()
            fg = Color(255, 255, 160)

        self._lbl.setBackground(bg)
        self._lbl.setForeground(fg)
        self._lbl.setBorder(EmptyBorder(3, 8, 3, 8))
        return self._lbl


class BatchPanel(JPanel):
    
    def __init__(self, batch_id, colors_map_fn, font_size, on_select_result, on_delete_ids, ext):
        JPanel.__init__(self, BorderLayout())
        self.setBackground(Color(28, 28, 28))
        self.batch_id         = batch_id
        self._colors_map_fn   = colors_map_fn
        self._font_size       = font_size
        self.results          = []
        self._on_select_result = on_select_result
        self._on_delete_ids    = on_delete_ids
        self.ext              = ext
        self._next_local_id   = 1
        self._all_columns     = {}
        self._build()

    def _build(self):
        sz = self._font_size

        self.resModel = DefaultTableModel(list(ALL_RESULT_COLUMNS), 0)
        self.resTable = JTable(self.resModel)
        self.resTable.setBackground(Color(28, 28, 28))
        self.resTable.setForeground(Color(220, 220, 220))
        self.resTable.setSelectionBackground(Color(80, 60, 20))
        self.resTable.setGridColor(Color(15, 15, 15))
        self.resTable.setShowGrid(True)
        self.resTable.setIntercellSpacing(Dimension(1, 2))
        self.resTable.setFont(Font("Monospaced", Font.BOLD, sz))
        self.resTable.setRowHeight(sz + 16)
        self.resTable.setAutoCreateRowSorter(False)
        self.resTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

        renderer = ColoredRowRenderer(self._colors_map_fn, sz)
        width_map = {"ID": 45, "Role": 200, "Status": 60, "Size": 70, "Time": 150,
                     "Host": 150, "Method": 70, "URL": 260, "Params": 220, "Match": 55}
        for name in ALL_RESULT_COLUMNS:
            col_idx = self.resModel.findColumn(name)
            tc = self.resTable.getColumnModel().getColumn(col_idx)
            tc.setCellRenderer(renderer)
            tc.setPreferredWidth(width_map.get(name, 120))
            self._all_columns[name] = tc

        header = self.resTable.getTableHeader()
        header.setBackground(Color(20, 20, 20))
        header.setForeground(Color(255, 180, 0))
        header.setFont(Font("Monospaced", Font.BOLD, sz))

        self.resTable.getSelectionModel().addListSelectionListener(self._onRowSelect)
        self.resTable.addMouseListener(self._makeMouseListener())

        initial_cols = self.ext.get_visible_columns() if self.ext else DEFAULT_VISIBLE_COLUMNS
        self._apply_visible_columns(initial_cols)

        resScroll = JScrollPane(self.resTable)
        self.add(resScroll, BorderLayout.CENTER)

    def _apply_visible_columns(self, visible_names):
        cm = self.resTable.getColumnModel()
        while cm.getColumnCount() > 0:
            cm.removeColumn(cm.getColumn(0))
        for name in ALL_RESULT_COLUMNS:
            if name in visible_names and name in self._all_columns:
                cm.addColumn(self._all_columns[name])

    def _row_values(self, r):
        match_mark = u""
        if self.ext:
            s = self.ext.get_search_text()
            if s:
                match_mark = u"\u2713" if self.ext.result_matches_search(r, s) else u"\u2717"
        return [
            r.get("local_id", r.get("id", 0)), r.get("role", ""), r.get("status", ""), r.get("size", 0),
            r.get("time", ""), r.get("host", ""), r.get("method", ""), r.get("url", ""),
            r.get("params", ""), match_mark
        ]

    def add_result(self, result):
        if not result.get("local_id"):
            result["local_id"] = self._next_local_id
            self._next_local_id += 1
        self.results.append(result)
        self.resModel.insertRow(0, self._row_values(result))

    def _sorted_results(self):
        mode = self.ext.get_sort_mode() if self.ext else None
        if not mode:
            return list(reversed(self.results))  
        key, order = mode
        
        if key == "size":
            keyfn = lambda r: r.get("size", 0)
        elif key == "match":
            
            keyfn = lambda r: 1 if (self.ext and self.ext.get_search_text() and self.ext.result_matches_search(r, self.ext.get_search_text())) else 0
        else:
            keyfn = lambda r: r.get("local_id", r.get("id", 0))
            
        return sorted(self.results, key=keyfn, reverse=(order == "desc"))

    def refresh_table(self):
        self._next_local_id = 1
        for r in self.results:
            if not r.get("local_id"):
                r["local_id"] = self._next_local_id
            self._next_local_id = max(self._next_local_id, r["local_id"] + 1)

        self.resModel.setRowCount(0)
        for r in self._sorted_results():
            self.resModel.addRow(self._row_values(r))

    def update_font(self, sz):
        self._font_size = sz
        self.resTable.setFont(Font("Monospaced", Font.BOLD, sz))
        self.resTable.setRowHeight(sz + 16)
        self.resTable.getTableHeader().setFont(Font("Monospaced", Font.BOLD, sz))

    def _onRowSelect(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.resTable.getSelectedRow()
        if row < 0: return
        mr = self.resTable.convertRowIndexToModel(row)
        id_col = self.resModel.findColumn("ID")
        try:
            row_id = int(str(self.resModel.getValueAt(mr, id_col)))
        except:
            return
        for r in self.results:
            if r.get("local_id", r.get("id", 0)) == row_id:
                self._on_select_result(r)
                break

    def _makeMouseListener(self):
        panel = self
        class ML(MouseAdapter):
            def mousePressed(self, e):
                if e.isPopupTrigger() or e.getButton() == MouseEvent.BUTTON3:
                    ML._show(e)
            def mouseReleased(self, e):
                if e.isPopupTrigger() or e.getButton() == MouseEvent.BUTTON3:
                    ML._show(e)
            @staticmethod
            def _show(e):
                row = panel.resTable.rowAtPoint(e.getPoint())
                if row < 0: return
                if not panel.resTable.isRowSelected(row):
                    panel.resTable.setRowSelectionInterval(row, row)
                menu = JPopupMenu()
                mi_del = JMenuItem("Delete")
                mi_del.addActionListener(lambda ev: panel._deleteRow())
                menu.add(mi_del)
                menu.show(panel.resTable, e.getX(), e.getY())
        return ML()

    def _deleteRow(self):
        rows = sorted(
            [self.resTable.convertRowIndexToModel(r) for r in self.resTable.getSelectedRows()],
            reverse=True
        )
        id_col = self.resModel.findColumn("ID")
        local_ids_to_del = set()
        for mr in rows:
            try:
                local_ids_to_del.add(int(str(self.resModel.getValueAt(mr, id_col))))
            except:
                pass
            self.resModel.removeRow(mr)

        global_ids_to_del = set()
        kept = []
        for r in self.results:
            if r.get("local_id", r.get("id", 0)) in local_ids_to_del:
                global_ids_to_del.add(r.get("id"))
            else:
                kept.append(r)
        self.results = kept
        if self._on_delete_ids:
            self._on_delete_ids(global_ids_to_del)

class KeyCellRenderer(TableCellRenderer):
    def __init__(self, ext, container_fn, base_font_size):
        self._ext = ext
        self._container_fn = container_fn
        self._fsz = base_font_size
        self._lbl = JLabel()
        self._lbl.setOpaque(True)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        key = _u(value)
        model = table.getModel()
        try:
            item_type = _u(model.getValueAt(row, 0))
        except:
            item_type = u"Header"
        try:
            container = self._container_fn()
        except:
            container = u""

        pinned = bool(key) and self._ext.has_grep_pattern(item_type, key, container)

        self._lbl.setText((u"\U0001F3AF " + key) if pinned else key)
        self._lbl.setFont(Font("Monospaced", Font.BOLD if pinned else Font.PLAIN, self._fsz))
        self._lbl.setToolTipText(
            u"This Key has a saved Grab-Value regex fingerprint for this Container - "
            u"its Value will be re-extracted automatically on 'Update From Container'."
            if pinned else None)

        if isSelected:
            self._lbl.setBackground(Color(90, 68, 24))
            self._lbl.setForeground(Color(255, 235, 190))
        else:
            self._lbl.setBackground(Color(46, 46, 50))
            self._lbl.setForeground(Color(255, 210, 100) if pinned else Color(225, 225, 225))
        self._lbl.setBorder(EmptyBorder(1, 4, 1, 4))
        return self._lbl


class RolePanel(JPanel):
    def __init__(self, extender, role_name="", color_hex=None, items=None, container="", endpoint=""):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.ext = extender
        self.color_hex = color_hex or DEFAULT_COLORS[len(extender.role_panels) % len(DEFAULT_COLORS)]
        self.setBackground(Color(38, 38, 42))
        self.setBorder(BorderFactory.createCompoundBorder(
            LineBorder(hex_to_color(self.color_hex), 2, True),
            EmptyBorder(8, 10, 10, 10)
        ))
        self.setAlignmentX(Component.LEFT_ALIGNMENT)

        sz = extender._current_font_size

        
        top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        top.setBackground(Color(38, 38, 42))
        top.setAlignmentX(Component.LEFT_ALIGNMENT)

        self.colorBtn = JButton("  ")
        self.colorBtn.setBackground(hex_to_color(self.color_hex))
        self.colorBtn.setPreferredSize(Dimension(30, 26))
        self.colorBtn.setBorder(LineBorder(Color(15, 15, 15), 1))
        self.colorBtn.setFocusPainted(False)
        self.colorBtn.addActionListener(lambda e: self._pickColor())
        top.add(self.colorBtn)

        lblRole = JLabel("Role:")
        lblRole.setForeground(Color(200, 200, 200))
        lblRole.setFont(Font("Monospaced", Font.BOLD, sz))
        top.add(lblRole)
        self.roleField = JTextField(role_name, max(18, len(role_name) + 2))
        self.roleField.setBackground(Color(50, 50, 55))
        self.roleField.setForeground(Color(235, 235, 235))
        self.roleField.setCaretColor(Color(255, 190, 60))
        self.roleField.setFont(Font("Monospaced", Font.BOLD, sz))
        self.roleField.setBorder(BorderFactory.createCompoundBorder(
            LineBorder(Color(70, 70, 75), 1), EmptyBorder(3, 6, 3, 6)
        ))
        top.add(self.roleField)

        rp_self = self
        class _RoleNameListener(DocumentListener):
            def insertUpdate(self, e): rp_self._update_role_field_width(); rp_self.ext._on_role_renamed(rp_self)
            def removeUpdate(self, e): rp_self._update_role_field_width(); rp_self.ext._on_role_renamed(rp_self)
            def changedUpdate(self, e): rp_self._update_role_field_width(); rp_self.ext._on_role_renamed(rp_self)
        self.roleField.getDocument().addDocumentListener(_RoleNameListener())

        lblContainer = JLabel("Container:")
        lblContainer.setForeground(Color(200, 200, 200))
        lblContainer.setFont(Font("Monospaced", Font.BOLD, sz))
        top.add(lblContainer)
        self.containerField = JTextField(container, 16)
        self.containerField.setToolTipText(
            "Firefox container name for this role (must match the container "
            "name exactly, e.g. 'Admin'). Used to auto-update headers/params "
            "from the latest captured request tagged with that container."
        )
        self.containerField.setBackground(Color(50, 50, 55))
        self.containerField.setForeground(Color(235, 235, 235))
        self.containerField.setCaretColor(Color(255, 190, 60))
        self.containerField.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.containerField.setBorder(BorderFactory.createCompoundBorder(
            LineBorder(Color(70, 70, 75), 1), EmptyBorder(3, 6, 3, 6)
        ))
        top.add(self.containerField)

        rp_self2 = self
        class _ContainerNameListener(DocumentListener):
            def insertUpdate(self, e): rp_self2._repaint_items_table()
            def removeUpdate(self, e): rp_self2._repaint_items_table()
            def changedUpdate(self, e): rp_self2._repaint_items_table()
        self.containerField.getDocument().addDocumentListener(_ContainerNameListener())

        lblEndpoint = JLabel("Endpoint:")
        lblEndpoint.setForeground(Color(200, 200, 200))
        lblEndpoint.setFont(Font("Monospaced", Font.BOLD, sz))
        top.add(lblEndpoint)
        self.endpointField = JTextField(endpoint, 16)
        self.endpointField.setToolTipText(
            "Optional. Restrict 'Update From Container' to requests matching "
            "this METHOD + path, e.g. 'POST /graph'. Prevents picking up "
            "headers/cookies from an unrelated request that happens to lack "
            "the right session (which was causing 403s). Leave blank to "
            "search all captured requests for this container, like before."
        )
        self.endpointField.setBackground(Color(50, 50, 55))
        self.endpointField.setForeground(Color(235, 235, 235))
        self.endpointField.setCaretColor(Color(255, 190, 60))
        self.endpointField.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.endpointField.setBorder(BorderFactory.createCompoundBorder(
            LineBorder(Color(70, 70, 75), 1), EmptyBorder(3, 6, 3, 6)
        ))
        top.add(self.endpointField)

        updBtn = JButton("Update From Container")
        updBtn.setBackground(Color(60, 120, 100))
        updBtn.setForeground(Color.WHITE)
        updBtn.setFocusPainted(False)
        updBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        updBtn.addActionListener(lambda e: self.ext.update_role_from_container(self, notify=True))
        top.add(updBtn)

        applyEpBtn = JButton("\u26a1 Apply Endpoint To ALL Roles")
        applyEpBtn.setBackground(Color(80, 90, 150))
        applyEpBtn.setForeground(Color.WHITE)
        applyEpBtn.setFocusPainted(False)
        applyEpBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        applyEpBtn.addActionListener(lambda e: self._apply_endpoint_to_all_roles())
        top.add(applyEpBtn)

        delBtn = JButton("Delete Role")
        delBtn.setBackground(Color(150, 55, 55))
        delBtn.setForeground(Color.WHITE)
        delBtn.setFocusPainted(False)
        delBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        delBtn.addActionListener(lambda e: self.ext._delete_role_panel(self))
        top.add(delBtn)

        self.add(top)

        hint = JLabel("e.g.  Key: X-Csrf-Token:  |  Endpoint: POST /graph  (leave Endpoint blank to search all traffic)  |  \U0001F3AF = Key has a saved Grab-Value regex for this Container")
        hint.setForeground(Color(130, 130, 140))
        hint.setFont(Font("Monospaced", Font.ITALIC, max(10, sz - 2)))
        hint.setBorder(EmptyBorder(0, 6, 4, 6))
        hint.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.add(hint)

        self.itemsModel = DefaultTableModel(["Type", "Key", "Value"], 0)
        self.itemsTable = JTable(self.itemsModel)
        self.itemsTable.setBackground(Color(46, 46, 50))
        self.itemsTable.setForeground(Color(225, 225, 225))
        self.itemsTable.setSelectionBackground(Color(90, 68, 24))
        self.itemsTable.setSelectionForeground(Color(255, 235, 190))
        self.itemsTable.setGridColor(Color(64, 64, 68))
        self.itemsTable.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.itemsTable.setRowHeight(sz + 14)
        self.itemsTable.setIntercellSpacing(Dimension(1, 3))
        self.itemsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.itemsTable.getColumnModel().getColumn(0).setPreferredWidth(120)
        self.itemsTable.getColumnModel().getColumn(1).setPreferredWidth(230)
        self.itemsTable.getColumnModel().getColumn(2).setPreferredWidth(340)
        combo = JComboBox(REPLACE_TYPES)
        self.itemsTable.getColumnModel().getColumn(0).setCellEditor(DefaultCellEditor(combo))
        self.itemsTable.getColumnModel().getColumn(1).setCellEditor(DefaultCellEditor(JTextField()))
        self.itemsTable.getColumnModel().getColumn(2).setCellEditor(DefaultCellEditor(JTextField()))
        self.itemsTable.getColumnModel().getColumn(1).setCellRenderer(
            KeyCellRenderer(self.ext, self.get_container_name, sz))
        self.itemsTable.getTableHeader().setBackground(Color(26, 26, 28))
        self.itemsTable.getTableHeader().setForeground(Color(255, 195, 70))
        self.itemsTable.getTableHeader().setFont(Font("Monospaced", Font.BOLD, sz))
        self.itemsTable.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.itemsTable.setPreferredScrollableViewportSize(Dimension(690, sz + 14))
        self.itemsTable.getTableHeader().setAlignmentX(Component.LEFT_ALIGNMENT)

        for it in (items or []):
            self.itemsModel.addRow([it.get("type", "Header"), it.get("key", ""), it.get("val", "")])
        self._update_table_size()

        self.itemsTable.setMaximumSize(Dimension(2000, 4000))
        self.add(self.itemsTable.getTableHeader())
        self.add(self.itemsTable)

        itemBtns = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        itemBtns.setBackground(Color(38, 38, 42))
        itemBtns.setAlignmentX(Component.LEFT_ALIGNMENT)
        addItemBtn = JButton("+ Add Header/Parameter")
        addItemBtn.setBackground(Color(65, 110, 170))
        addItemBtn.setForeground(Color.WHITE)
        addItemBtn.setFocusPainted(False)
        addItemBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        addItemBtn.addActionListener(lambda e: self._addItem())
        itemBtns.add(addItemBtn)

        rmItemBtn = JButton("- Remove Selected Item")
        rmItemBtn.setBackground(Color(130, 60, 60))
        rmItemBtn.setForeground(Color.WHITE)
        rmItemBtn.setFocusPainted(False)
        rmItemBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        rmItemBtn.addActionListener(lambda e: self._removeSelectedItem())
        itemBtns.add(rmItemBtn)

        grabBtn = JButton("\U0001F3AF Grab Value From Traffic")
        grabBtn.setBackground(Color(150, 100, 40))
        grabBtn.setForeground(Color.WHITE)
        grabBtn.setFocusPainted(False)
        grabBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        grabBtn.addActionListener(lambda e: self._grab_value_from_traffic())
        itemBtns.add(grabBtn)

        applyAllBtn = JButton("\u26a1 Apply Item To ALL Roles")
        applyAllBtn.setBackground(Color(80, 90, 150))
        applyAllBtn.setForeground(Color.WHITE)
        applyAllBtn.setFocusPainted(False)
        applyAllBtn.setBorder(EmptyBorder(4, 10, 4, 10))
        applyAllBtn.addActionListener(lambda e: self._apply_item_to_all_roles())
        itemBtns.add(applyAllBtn)

        self.add(itemBtns)

    def _pickColor(self):
        chosen = JColorChooser.showDialog(self, "Pick Role Color", hex_to_color(self.color_hex))
        if chosen:
            self.color_hex = color_to_hex(chosen)
            self.colorBtn.setBackground(chosen)
            self.setBorder(LineBorder(chosen, 2))

    def _update_role_field_width(self):
        text = self.roleField.getText()
        cols = max(18, len(text) + 2)
        self.roleField.setColumns(cols)
        self.roleField.revalidate()
        self.revalidate()
        self.repaint()

    def _repaint_items_table(self):
        if hasattr(self, "itemsTable"):
            self.itemsTable.repaint()

    def _addItem(self):
        self.itemsModel.addRow(["Header", "", ""])
        self._update_table_size()

    def _removeSelectedItem(self):
        rows = sorted(self.itemsTable.getSelectedRows(), reverse=True)
        for r in rows:
            self.itemsModel.removeRow(r)
        self._update_table_size()

    def _grab_value_from_traffic(self):
        row = self.itemsTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self,
                "Select a Header/Parameter row first (the row whose value you want to grab from traffic).")
            return
        item_type = str(self.itemsModel.getValueAt(row, 0) or "Header").strip()
        key       = str(self.itemsModel.getValueAt(row, 1) or "").strip()
        if not key:
            JOptionPane.showMessageDialog(self,
                "That row has no Key set yet - type the Header/Parameter name first.")
            return

        container = self.get_container_name()

        owner = SwingUtilities.getWindowAncestor(self)
        dlg = GrabValueDialog(owner)
        dlg.setVisible(True)
        res = dlg.result
        if not res:
            return  

        value = res["value"]
        self.itemsModel.setValueAt(value, row, 2)
        self.ext.save_grep_pattern(item_type, key, res["regex"], res.get("prefix", u""), res.get("suffix", u""),
                                    container=container)
        self._repaint_items_table()

        JOptionPane.showMessageDialog(self,
            "Value captured and regex fingerprint saved for '%s' (Container: %s).\n\n"
            "This fingerprint only applies to THIS container, so it will never be\n"
            "reused to extract a value for a different role/container that happens\n"
            "to use the same Header/Parameter name.\n\n"
            "Use '\u26a1 Apply Item To ALL Roles' below if you also want to push this\n"
            "captured Key/Value to specific other roles." % (key, container or "(none)"))

    def _apply_item_to_all_roles(self):

        row = self.itemsTable.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self, "Select a Header/Parameter row first.")
            return
        item_type = str(self.itemsModel.getValueAt(row, 0) or "Header").strip()
        key       = str(self.itemsModel.getValueAt(row, 1) or "").strip()
        if not key:
            JOptionPane.showMessageDialog(self, "That row has no Key set yet.")
            return
        self.ext.open_apply_to_roles_dialog(self, item_type, key, self.get_container_name())

    def _apply_endpoint_to_all_roles(self):

        endpoint = self.get_endpoint()
        confirm = JOptionPane.showConfirmDialog(
            self,
            "Apply Endpoint '%s' to ALL other roles?" % (endpoint or "(blank)"),
            "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return
        n = self.ext.bulk_apply_endpoint_to_all_roles(endpoint, exclude_rp=self)
        JOptionPane.showMessageDialog(self, "Applied Endpoint to %d other role(s)." % n)

    def _update_table_size(self):
        sz = self.ext._current_font_size
        rows = max(1, self.itemsModel.getRowCount())
        h = rows * (sz + 14) + 4
        self.itemsTable.setPreferredScrollableViewportSize(Dimension(690, h))
        self.itemsTable.setPreferredSize(Dimension(690, h))
        self.revalidate()
        self.repaint()

    def update_font(self, sz):
        self.itemsTable.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.itemsTable.setRowHeight(sz + 14)
        self.itemsTable.getTableHeader().setFont(Font("Monospaced", Font.BOLD, sz))
        self.roleField.setFont(Font("Monospaced", Font.BOLD, sz))
        self.containerField.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.endpointField.setFont(Font("Monospaced", Font.PLAIN, sz))
        self._update_table_size()

    def get_role_name(self):
        return self.roleField.getText().strip()

    def get_container_name(self):
        return self.containerField.getText().strip()

    def get_endpoint(self):
        return self.endpointField.getText().strip()

    def get_entry(self):
        items = []
        for r in range(self.itemsModel.getRowCount()):
            t = str(self.itemsModel.getValueAt(r, 0) or "Header").strip()
            k = str(self.itemsModel.getValueAt(r, 1) or "").strip()
            v = str(self.itemsModel.getValueAt(r, 2) or "").strip()
            if not k:
                continue
            items.append({"type": t, "key": k, "val": v})
        return {"role": self.get_role_name(), "color": self.color_hex, "items": items,
                "container": self.get_container_name(), "endpoint": self.get_endpoint()}


class GrabValueDialog(JDialog):

    def __init__(self, parent, initial_text=u""):
        JDialog.__init__(self, parent, "Grab Value From Traffic (Grep Extract)", True)
        self.result  = None
        self._prefix = u""
        self._suffix = u""
        self._value  = u""
        self._regex  = u""
        self._build(initial_text)
        self.setSize(780, 580)
        self.setLocationRelativeTo(parent)

    def _build(self, initial_text):
        content = JPanel(BorderLayout())
        content.setBackground(Color(28, 28, 28))
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        instr = JLabel(
            "<html>Paste the raw response (or request) text below, then "
            "select/highlight the exact value you want, and click 'Build "
            "Regex From Selection'. A few characters before/after your "
            "selection become a fixed fingerprint, saved for reuse.</html>")
        instr.setForeground(Color(210, 210, 210))
        instr.setFont(Font("Monospaced", Font.PLAIN, 12))
        instr.setBorder(EmptyBorder(0, 0, 8, 0))
        content.add(instr, BorderLayout.NORTH)

        self.textArea = JTextArea(initial_text)
        self.textArea.setLineWrap(True)
        self.textArea.setBackground(Color(22, 22, 22))
        self.textArea.setForeground(Color(220, 220, 220))
        self.textArea.setCaretColor(Color(255, 190, 60))
        self.textArea.setSelectionColor(Color(255, 180, 0))
        self.textArea.setSelectedTextColor(Color(0, 0, 0))
        self.textArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        scroll = JScrollPane(self.textArea)
        content.add(scroll, BorderLayout.CENTER)

        south = JPanel()
        south.setLayout(BoxLayout(south, BoxLayout.Y_AXIS))
        south.setBackground(Color(28, 28, 28))

        ctxBar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        ctxBar.setBackground(Color(28, 28, 28))
        lbl = JLabel("Fingerprint context (chars before/after):")
        lbl.setForeground(Color(200, 200, 200))
        lbl.setFont(Font("Monospaced", Font.PLAIN, 12))
        ctxBar.add(lbl)
        self.spnCtx = JSpinner(SpinnerNumberModel(15, 3, 80, 1))
        ctxBar.add(self.spnCtx)
        buildBtn = JButton("Build Regex From Selection")
        buildBtn.setBackground(Color(65, 110, 170))
        buildBtn.setForeground(Color.WHITE)
        buildBtn.setFocusPainted(False)
        buildBtn.addActionListener(lambda e: self._build_regex())
        ctxBar.add(buildBtn)
        south.add(ctxBar)

        self.lblValue = JLabel(u"Captured value: \u2014")
        self.lblValue.setForeground(Color(255, 210, 100))
        self.lblValue.setFont(Font("Monospaced", Font.BOLD, 13))
        self.lblValue.setBorder(EmptyBorder(4, 8, 0, 8))
        south.add(self.lblValue)

        self.lblRegex = JLabel(u"Regex: \u2014")
        self.lblRegex.setForeground(Color(150, 210, 255))
        self.lblRegex.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.lblRegex.setBorder(EmptyBorder(2, 8, 4, 8))
        south.add(self.lblRegex)

        self.lblCheck = JLabel(" ")
        self.lblCheck.setFont(Font("Monospaced", Font.BOLD, 12))
        self.lblCheck.setBorder(EmptyBorder(0, 8, 6, 8))
        south.add(self.lblCheck)

        btnBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btnBar.setBackground(Color(28, 28, 28))
        self.okBtn = JButton("Save & Use This Value")
        self.okBtn.setBackground(Color(45, 140, 80))
        self.okBtn.setForeground(Color.WHITE)
        self.okBtn.setFocusPainted(False)
        self.okBtn.setEnabled(False)
        self.okBtn.addActionListener(lambda e: self._on_ok())
        cancelBtn = JButton("Cancel")
        cancelBtn.setBackground(Color(90, 90, 90))
        cancelBtn.setForeground(Color.WHITE)
        cancelBtn.setFocusPainted(False)
        cancelBtn.addActionListener(lambda e: self.dispose())
        btnBar.add(cancelBtn)
        btnBar.add(self.okBtn)
        south.add(btnBar)

        content.add(south, BorderLayout.SOUTH)
        self.setContentPane(content)

    def _build_regex(self):
        start = self.textArea.getSelectionStart()
        end   = self.textArea.getSelectionEnd()
        if start == end:
            JOptionPane.showMessageDialog(self,
                "Highlight the value first (click-drag over it in the text box above).")
            return
        text = self.textArea.getText()
        try:
            ctx = int(str(self.spnCtx.getValue()))
        except:
            ctx = 15
        prefix = text[max(0, start - ctx):start]
        suffix = text[end:min(len(text), end + ctx)]
        value  = text[start:end]

        regex = _build_fingerprint_regex(prefix, suffix)

        self._prefix, self._suffix, self._value, self._regex = prefix, suffix, value, regex
        self.lblValue.setText(u"Captured value: %s" % value)
        self.lblRegex.setText(u"Regex: %s" % regex)

        try:
            m = re.search(regex, text, re.DOTALL)
            if m and m.group(1) == value:
                self.lblCheck.setText(u"\u2713 Regex matches the highlighted value correctly.")
                self.lblCheck.setForeground(Color(120, 220, 140))
                self.okBtn.setEnabled(True)
            else:
                self.lblCheck.setText(
                    u"\u2717 Regex built but didn't re-match the exact selection - try a different context length.")
                self.lblCheck.setForeground(Color(230, 120, 120))
                self.okBtn.setEnabled(False)
        except Exception as ex:
            self.lblCheck.setText(u"\u2717 Regex error: %s" % str(ex))
            self.lblCheck.setForeground(Color(230, 120, 120))
            self.okBtn.setEnabled(False)

    def _on_ok(self):
        self.result = {
            "value":  self._value,
            "regex":  self._regex,
            "prefix": self._prefix,
            "suffix": self._suffix,
        }
        self.dispose()


class ApplyToRolesDialog(JDialog):

    def __init__(self, parent, role_names, item_type, key, exclude_index=None, has_regex=False):
        JDialog.__init__(self, parent, "Apply Header/Parameter To Roles", True)
        self.confirmed        = False
        self.selected_indices = []
        self.checks           = []
        self._build(role_names, item_type, key, exclude_index, has_regex)
        self.setSize(920, 640)
        self.setLocationRelativeTo(parent)

    def _build(self, role_names, item_type, key, exclude_index, has_regex):
        content = JPanel(BorderLayout())
        content.setBackground(Color(28, 28, 28))
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        if has_regex:
            head_html = (u"<html><b>%s</b> &nbsp; Key: <b>%s</b><br>"
                         u"<font color=#96D2FF>\U0001F3AF saved regex fingerprint will also be copied</font><br>"
                         u"<font color=#A0A0A0>(Value is NOT copied - each role keeps its own)</font></html>"
                         % (item_type, key))
        else:
            head_html = (u"<html><b>%s</b> &nbsp; Key: <b>%s</b><br>"
                         u"<font color=#A0A0A0>(Value is NOT copied - each role keeps its own)</font></html>"
                         % (item_type, key))
        head = JLabel(head_html)
        head.setForeground(Color(255, 210, 100))
        head.setFont(Font("Monospaced", Font.PLAIN, 13))
        head.setBorder(EmptyBorder(0, 4, 8, 4))
        content.add(head, BorderLayout.NORTH)

        listPanel = JPanel()
        listPanel.setLayout(BoxLayout(listPanel, BoxLayout.Y_AXIS))
        listPanel.setBackground(Color(28, 28, 28))
        for i, name in enumerate(role_names):
            cb = JCheckBox(name, i != exclude_index)
            cb.setEnabled(i != exclude_index)
            cb.setBackground(Color(28, 28, 28))
            cb.setForeground(Color(220, 220, 220) if i != exclude_index else Color(120, 120, 120))
            cb.setFont(Font("Monospaced", Font.PLAIN, 13))
            listPanel.add(cb)
            self.checks.append(cb)
        scroll = JScrollPane(listPanel)
        content.add(scroll, BorderLayout.CENTER)

        btnBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btnBar.setBackground(Color(28, 28, 28))

        selAllBtn = JButton("Select All")
        selAllBtn.setFocusPainted(False)
        selAllBtn.addActionListener(lambda e: [cb.setSelected(True) for cb in self.checks if cb.isEnabled()])
        selNoneBtn = JButton("Select None")
        selNoneBtn.setFocusPainted(False)
        selNoneBtn.addActionListener(lambda e: [cb.setSelected(False) for cb in self.checks if cb.isEnabled()])

        cancelBtn = JButton("Cancel")
        cancelBtn.setBackground(Color(90, 90, 90))
        cancelBtn.setForeground(Color.WHITE)
        cancelBtn.setFocusPainted(False)
        cancelBtn.addActionListener(lambda e: self.dispose())

        okBtn = JButton("Apply")
        okBtn.setBackground(Color(45, 140, 80))
        okBtn.setForeground(Color.WHITE)
        okBtn.setFocusPainted(False)
        okBtn.addActionListener(lambda e: self._on_ok())

        btnBar.add(selAllBtn)
        btnBar.add(selNoneBtn)
        btnBar.add(cancelBtn)
        btnBar.add(okBtn)
        content.add(btnBar, BorderLayout.SOUTH)

        self.setContentPane(content)

    def _on_ok(self):
        selected = [i for i, cb in enumerate(self.checks) if cb.isSelected()]
        if not selected:
            JOptionPane.showMessageDialog(self, "Select at least one role first.")
            return
        self.selected_indices = selected
        self.confirmed = True
        self.dispose()


class DeleteRoleDialog(JDialog):

    def __init__(self, parent, role_names):
        JDialog.__init__(self, parent, "Delete Role(s)", True)
        self.confirmed        = False
        self.selected_indices = []
        self.checks           = []
        self._build(role_names)
        self.setMinimumSize(Dimension(450, 300))
        self.pack()
        self.setLocationRelativeTo(parent) 

    def _build(self, role_names):
        content = JPanel(BorderLayout())
        content.setBackground(Color(28, 28, 28))
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        head = JLabel("Select role(s) to permanently delete:")
        head.setForeground(Color(230, 120, 120))
        head.setFont(Font("Monospaced", Font.BOLD, 13))
        head.setBorder(EmptyBorder(0, 4, 8, 4))
        content.add(head, BorderLayout.NORTH)

        listPanel = JPanel()
        listPanel.setLayout(BoxLayout(listPanel, BoxLayout.Y_AXIS))
        listPanel.setBackground(Color(28, 28, 28))
        for name in role_names:
            cb = JCheckBox(name, False)
            cb.setBackground(Color(28, 28, 28))
            cb.setForeground(Color(220, 220, 220))
            cb.setFont(Font("Monospaced", Font.PLAIN, 13))
            listPanel.add(cb)
            self.checks.append(cb)
        content.add(JScrollPane(listPanel), BorderLayout.CENTER)

        btnBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btnBar.setBackground(Color(28, 28, 28))
        selAllBtn = JButton("Select All")
        selAllBtn.setFocusPainted(False)
        selAllBtn.addActionListener(lambda e: [cb.setSelected(True) for cb in self.checks])
        selNoneBtn = JButton("Select None")
        selNoneBtn.setFocusPainted(False)
        selNoneBtn.addActionListener(lambda e: [cb.setSelected(False) for cb in self.checks])
        cancelBtn = JButton("Cancel")
        cancelBtn.setBackground(Color(90, 90, 90))
        cancelBtn.setForeground(Color.WHITE)
        cancelBtn.setFocusPainted(False)
        cancelBtn.addActionListener(lambda e: self.dispose())
        okBtn = JButton("Delete Selected")
        okBtn.setBackground(Color(150, 55, 55))
        okBtn.setForeground(Color.WHITE)
        okBtn.setFocusPainted(False)
        okBtn.addActionListener(lambda e: self._on_ok())
        btnBar.add(selAllBtn)
        btnBar.add(selNoneBtn)
        btnBar.add(cancelBtn)
        btnBar.add(okBtn)
        content.add(btnBar, BorderLayout.SOUTH)

        self.setContentPane(content)

    def _on_ok(self):
        sel = [i for i, cb in enumerate(self.checks) if cb.isSelected()]
        if not sel:
            JOptionPane.showMessageDialog(self, "Select at least one role.")
            return
        self.selected_indices = sel
        self.confirmed = True
        self.dispose()


class DeleteItemDialog(JDialog):

    def __init__(self, parent):
        JDialog.__init__(self, parent, "Delete Header/Parameter From ALL Roles", True)
        self.confirmed = False
        self.item_type = "Header"
        self.key       = u""
        self._build()
        self.setMinimumSize(Dimension(450, 220))
        self.pack()
        self.setLocationRelativeTo(parent)

    def _build(self):
        content = JPanel(BorderLayout())
        content.setBackground(Color(28, 28, 28))
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        note = JLabel("<html>Removes the matching row (Type+Key, case-insensitive) from<br>"
                       "EVERY role that has it. Each role's own Value is discarded with it.</html>")
        note.setForeground(Color(180, 180, 180))
        note.setFont(Font("Monospaced", Font.PLAIN, 12))
        note.setBorder(EmptyBorder(0, 2, 10, 2))
        content.add(note, BorderLayout.NORTH)

        form = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        form.setBackground(Color(28, 28, 28))
        lblT = JLabel("Type:")
        lblT.setForeground(Color(200, 200, 200))
        lblT.setFont(Font("Monospaced", Font.PLAIN, 13))
        form.add(lblT)
        self.combo = JComboBox(REPLACE_TYPES)
        form.add(self.combo)
        lblK = JLabel("  Key:")
        lblK.setForeground(Color(200, 200, 200))
        lblK.setFont(Font("Monospaced", Font.PLAIN, 13))
        form.add(lblK)
        self.fldKey = JTextField(20)
        form.add(self.fldKey)
        content.add(form, BorderLayout.CENTER)

        btnBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btnBar.setBackground(Color(28, 28, 28))
        cancelBtn = JButton("Cancel")
        cancelBtn.setBackground(Color(90, 90, 90))
        cancelBtn.setForeground(Color.WHITE)
        cancelBtn.setFocusPainted(False)
        cancelBtn.addActionListener(lambda e: self.dispose())
        okBtn = JButton("Delete From ALL Roles")
        okBtn.setBackground(Color(150, 55, 55))
        okBtn.setForeground(Color.WHITE)
        okBtn.setFocusPainted(False)
        okBtn.addActionListener(lambda e: self._on_ok())
        btnBar.add(cancelBtn)
        btnBar.add(okBtn)
        content.add(btnBar, BorderLayout.SOUTH)

        self.setContentPane(content)

    def _on_ok(self):
        key = self.fldKey.getText().strip()
        if not key:
            JOptionPane.showMessageDialog(self, "Enter a Key first.")
            return
        self.item_type = str(self.combo.getSelectedItem())
        self.key       = key
        self.confirmed = True
        self.dispose()


class ColumnFilterDialog(JDialog):
    def __init__(self, parent, all_columns, visible_columns):
        JDialog.__init__(self, parent, "Choose Visible Columns", True)
        self.confirmed = False
        self.selected  = list(visible_columns)
        self.checks    = []
        self._build(all_columns, visible_columns)
        self.setSize(320, 430)
        self.setLocationRelativeTo(parent)

    def _build(self, all_columns, visible_columns):
        content = JPanel(BorderLayout())
        content.setBackground(Color(28, 28, 28))
        content.setBorder(EmptyBorder(10, 10, 10, 10))

        head = JLabel("Columns shown in every Results group:")
        head.setForeground(Color(255, 195, 70))
        head.setFont(Font("Monospaced", Font.BOLD, 13))
        head.setBorder(EmptyBorder(0, 4, 8, 4))
        content.add(head, BorderLayout.NORTH)

        listPanel = JPanel()
        listPanel.setLayout(BoxLayout(listPanel, BoxLayout.Y_AXIS))
        listPanel.setBackground(Color(28, 28, 28))
        for name in all_columns:
            cb = JCheckBox(name, name in visible_columns)
            cb.setBackground(Color(28, 28, 28))
            cb.setForeground(Color(220, 220, 220))
            cb.setFont(Font("Monospaced", Font.PLAIN, 13))
            listPanel.add(cb)
            self.checks.append((name, cb))
        content.add(JScrollPane(listPanel), BorderLayout.CENTER)

        btnBar = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btnBar.setBackground(Color(28, 28, 28))
        cancelBtn = JButton("Cancel")
        cancelBtn.setBackground(Color(90, 90, 90))
        cancelBtn.setForeground(Color.WHITE)
        cancelBtn.setFocusPainted(False)
        cancelBtn.addActionListener(lambda e: self.dispose())
        okBtn = JButton("Apply")
        okBtn.setBackground(Color(45, 140, 80))
        okBtn.setForeground(Color.WHITE)
        okBtn.setFocusPainted(False)
        okBtn.addActionListener(lambda e: self._on_ok())
        btnBar.add(cancelBtn)
        btnBar.add(okBtn)
        content.add(btnBar, BorderLayout.SOUTH)

        self.setContentPane(content)

    def _on_ok(self):
        sel = [name for name, cb in self.checks if cb.isSelected()]
        if not sel:
            JOptionPane.showMessageDialog(self, "Select at least one column.")
            return
        self.selected  = sel
        self.confirmed = True
        self.dispose()


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        self.callbacks.setExtensionName("RoleSwitch")
        self.config    = self.load_config()
        self.results          = []
        self.history           = []
        self.current_display  = None
        self.current_hist_entry = None
        self._current_font_size = DEFAULT_FONT_SIZE
        self._saved_settings  = {}
        self._next_id         = [1]
        self._next_batch      = [1]
        self._next_hist_id    = [1]
        self._batch_panels    = []
        self.role_panels      = []
        self._visible_columns = list(DEFAULT_VISIBLE_COLUMNS)
        self._sort_mode        = None   
        self._search_text      = u""    
        self._search_scope     = "Both" 
        self._container_history = {}
        self._container_history_cap = 100
        self._results_lock = threading.Lock()
        self._grep_patterns = {}
        self._loadGrepPatterns()
        self._job_queue = LinkedBlockingQueue()
        self._worker = JobQueueWorker(self._job_queue)
        self._worker.setDaemon(True)
        self._worker.start()

        self._loadSettings()

        from java.util.concurrent import CountDownLatch
        latch = CountDownLatch(1)
        def _build_and_signal():
            try:
                self._build_ui()
            finally:
                latch.countDown()
        SwingUtilities.invokeLater(_build_and_signal)
        latch.await()

        self._loadResults()
        self._loadHistory()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        self.callbacks.printOutput("RoleSwitch GUI loaded.")

    def _enqueue_job(self, fn):
        self._job_queue.put(fn)

    def getTabCaption(self):
        return "RoleSwitch"

    def getUiComponent(self):
        return self.main_panel

    def getHttpService(self):
        return self.current_display["request"] and self.helpers.buildHttpService(
            self.current_display["host"], self.current_display["port"],
            self.current_display["protocol"] == "https") if self.current_display else None

    def getRequest(self):
        return self.current_display["request"] if self.current_display else None

    def getResponse(self):
        return self.current_display["response"] if self.current_display else None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            request = messageInfo.getRequest()
            if not request:
                return
            req_analyzed = self.helpers.analyzeRequest(messageInfo)
            req_headers = list(req_analyzed.getHeaders())
            container_name = None
            for h in req_headers:
                if ":" in h:
                    name, val = h.split(":", 1)
                    if name.strip().lower() == CONTAINER_HEADER_NAME.lower():
                        container_name = val.strip()
                        break
            if not container_name:
                return

            response = messageInfo.getResponse()  

            service = messageInfo.getHttpService()
            entry = {
                "request":  bytearray(request),
                "response": bytearray(response) if response else None,
                "host":     service.getHost(),
                "port":     service.getPort(),
                "protocol": service.getProtocol(),
                "time":     cairo_timestamp(),
            }
            key = _norm_container_name(container_name)
            hist = self._container_history.setdefault(key, [])
            hist.insert(0, entry)
            del hist[self._container_history_cap:]
        except Exception as ex:
            print("[Container Capture Error] " + str(ex))

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.setBackground(Color(28, 28, 28))
        self.tabs = JTabbedPane()
        self.tabs.setFont(Font("Monospaced", Font.BOLD, self._current_font_size))
        self._build_config_tab()
        self._build_results_tab()
        self._build_history_tab()
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

    def _build_config_tab(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(Color(24, 24, 26))

        title = JLabel("  RoleSwitch — Role Configuration")
        title.setFont(Font("Monospaced", Font.BOLD, 17))
        title.setForeground(Color(255, 195, 70))
        title.setBorder(EmptyBorder(12, 12, 12, 12))
        title.setOpaque(True)
        title.setBackground(Color(20, 20, 22))

        sz = self._current_font_size

        self._combo_updating = False
        selectorBar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 8))
        selectorBar.setBackground(Color(20, 20, 22))
        selectorBar.setBorder(EmptyBorder(2, 4, 2, 4))

        lblSel = JLabel("  Role:")
        lblSel.setForeground(Color(255, 195, 70))
        lblSel.setFont(Font("Monospaced", Font.BOLD, sz))
        selectorBar.add(lblSel)

        self.roleCombo = JComboBox()
        self.roleCombo.setFont(Font("Monospaced", Font.BOLD, sz))
        self.roleCombo.setBackground(Color(50, 50, 55))
        self.roleCombo.setForeground(Color(235, 235, 235))
        self.roleCombo.setPreferredSize(Dimension(420, 28))
        self.roleCombo.setMaximumRowCount(20)

        def _onComboAction(e):
            if self._combo_updating:
                return
            idx = self.roleCombo.getSelectedIndex()
            if idx >= 0:
                self._show_role_panel(idx)
        self.roleCombo.addActionListener(_onComboAction)
        selectorBar.add(self.roleCombo)

        def mkbtn(txt, bg, fn):
            b = JButton(txt)
            b.setBackground(bg)
            b.setForeground(Color.WHITE)
            b.setFont(Font("Monospaced", Font.BOLD, sz))
            b.setFocusPainted(False)
            b.setBorder(EmptyBorder(5, 12, 5, 12))
            b.addActionListener(lambda e: fn())
            return b

        selectorBar.add(mkbtn("+ Add New Role", Color(45, 140, 80), lambda: self._add_role_panel()))
        selectorBar.add(mkbtn("Update ALL Roles From Containers", Color(60, 120, 100),
                               self.update_all_roles_from_containers))
        selectorBar.add(mkbtn("\U0001F5D1 Delete Role...", Color(140, 40, 40),
                               self._open_delete_role_dialog))
        selectorBar.add(mkbtn("\U0001F5D1 Delete Header/Param From ALL Roles...", Color(150, 90, 40),
                               self._open_delete_item_dialog))

        northWrap = JPanel(BorderLayout())
        northWrap.add(title, BorderLayout.NORTH)
        northWrap.add(selectorBar, BorderLayout.SOUTH)
        outer.add(northWrap, BorderLayout.NORTH)

        self.roleDisplay = JPanel(BorderLayout())
        self.roleDisplay.setBackground(Color(24, 24, 26))
        self.roleDisplay.setBorder(EmptyBorder(10, 10, 10, 10))
        self._displayed_role_panel = None

        self.rolesScroll = JScrollPane(self.roleDisplay)
        self.rolesScroll.setBorder(EmptyBorder(0, 0, 0, 0))
        self.rolesScroll.getViewport().setBackground(Color(24, 24, 26))
        self.rolesScroll.getVerticalScrollBar().setUnitIncrement(16)
        outer.add(self.rolesScroll, BorderLayout.CENTER)

        for entry in self._config_to_role_entries(self.config):
            self._add_role_panel(entry.get("role", ""), entry.get("color"), entry.get("items", []),
                                  entry.get("container", ""), entry.get("endpoint", ""), select=False)
        if not self.role_panels:
            self._add_role_panel(select=False)
        self._rebuild_role_combo(select_panel=self.role_panels[0])

        btns = JPanel(FlowLayout(FlowLayout.LEFT, 10, 8))
        btns.setBackground(Color(20, 20, 22))
        btns.setBorder(EmptyBorder(4, 4, 4, 4))

        btns.add(mkbtn("Save", Color(65, 110, 170), self._on_save))
        btns.add(mkbtn("Load", Color(45, 110, 65),  self._on_load))
        btns.add(mkbtn("Export JSON...", Color(70, 130, 150), self._on_export))
        btns.add(mkbtn("Import JSON...", Color(70, 130, 150), self._on_import))

        lblFont = JLabel("  Font:")
        lblFont.setForeground(Color(190, 190, 190))
        lblFont.setFont(Font("Monospaced", Font.PLAIN, sz))
        btns.add(lblFont)
        self.spnFont = JSpinner(SpinnerNumberModel(self._current_font_size, 8, 28, 1))
        self.spnFont.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.spnFont.setPreferredSize(Dimension(60, 26))
        btns.add(self.spnFont)
        btns.add(mkbtn("Apply Font", Color(90, 70, 135), self._apply_font))

        lblRps = JLabel("  Req/sec:")
        lblRps.setForeground(Color(190, 190, 190))
        lblRps.setFont(Font("Monospaced", Font.PLAIN, sz))
        btns.add(lblRps)
        saved_rps = str(self._saved_settings.get("rps", "1"))
        self.fldRPS = JTextField(saved_rps, 5)
        self.fldRPS.setBackground(Color(50, 50, 55))
        self.fldRPS.setForeground(Color(235, 235, 235))
        self.fldRPS.setCaretColor(Color(255, 190, 60))
        self.fldRPS.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.fldRPS.setBorder(BorderFactory.createCompoundBorder(
            LineBorder(Color(70, 70, 75), 1), EmptyBorder(3, 6, 3, 6)
        ))
        btns.add(self.fldRPS)
        btns.add(mkbtn("Save Rate", Color(90, 70, 135), self._save_rps))
        lblThreads = JLabel("  Threads:")
        lblThreads.setForeground(Color(190, 190, 190))
        lblThreads.setFont(Font("Monospaced", Font.PLAIN, sz))
        btns.add(lblThreads)
        saved_threads = int(self._saved_settings.get("threads", 1))
        self.spnThreads = JSpinner(SpinnerNumberModel(saved_threads, 1, 50, 1))
        self.spnThreads.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.spnThreads.setPreferredSize(Dimension(60, 26))
        btns.add(self.spnThreads)

        outer.add(btns, BorderLayout.SOUTH)
        self.tabs.addTab("Config", outer)

    def _save_rps(self):
        try:
            val = float(self.fldRPS.getText().strip())
        except:
            JOptionPane.showMessageDialog(self.main_panel, "Req/sec must be a number.")
            return
        self._saveSettings()
        self._setStatus("Req/sec saved: %s (persists across restarts)" % val, Color(120, 200, 150))

    def _role_label(self, rp, idx):
        name = rp.get_role_name()
        return name if name else "(Unnamed Role %d)" % (idx + 1)

    def _rebuild_role_combo(self, select_panel=None):
        if not hasattr(self, "roleCombo"):
            return
        self._combo_updating = True
        try:
            labels = [self._role_label(rp, i) for i, rp in enumerate(self.role_panels)]
            self.roleCombo.setModel(DefaultComboBoxModel(labels))
            target_idx = 0
            if select_panel is not None and select_panel in self.role_panels:
                target_idx = self.role_panels.index(select_panel)
            if self.roleCombo.getItemCount() > 0:
                self.roleCombo.setSelectedIndex(target_idx)
        finally:
            self._combo_updating = False
        if self.roleCombo.getItemCount() > 0:
            self._show_role_panel(self.roleCombo.getSelectedIndex())

    def _on_role_renamed(self, rp):
        if not hasattr(self, "roleCombo"):
            return
        self._combo_updating = True
        try:
            labels = [self._role_label(p, i) for i, p in enumerate(self.role_panels)]
            self.roleCombo.setModel(DefaultComboBoxModel(labels))
            if rp in self.role_panels:
                self.roleCombo.setSelectedIndex(self.role_panels.index(rp))
        finally:
            self._combo_updating = False
    def _show_role_panel(self, idx):
        if not hasattr(self, "roleDisplay"):
            return
        if idx < 0 or idx >= len(self.role_panels):
            return
        rp = self.role_panels[idx]
        if getattr(self, "_displayed_role_panel", None) is rp:
            return
        rp._update_role_field_width()
        self.roleDisplay.removeAll()
        self.roleDisplay.add(rp, BorderLayout.NORTH)
        self.roleDisplay.revalidate()
        self.roleDisplay.repaint()
        self._displayed_role_panel = rp

    def _add_role_panel(self, role_name="", color_hex=None, items=None, container="", endpoint="", select=True):
        rp = RolePanel(self, role_name, color_hex, items, container, endpoint)
        self.role_panels.append(rp)
        if hasattr(self, "roleCombo"):
            self._rebuild_role_combo(select_panel=rp if select else None)
        return rp

    def _delete_role_panel(self, rp):
        if rp not in self.role_panels:
            return
        idx = self.role_panels.index(rp)
        self.role_panels.remove(rp)
        if getattr(self, "_displayed_role_panel", None) is rp:
            self._displayed_role_panel = None
        if not self.role_panels:
            self._add_role_panel(select=False)
        next_idx = min(idx, len(self.role_panels) - 1)
        self._rebuild_role_combo(select_panel=self.role_panels[next_idx])

    def _open_delete_role_dialog(self):
        """'🗑 Delete Role...' — bulk delete without having to open each role
        panel and click its own 'Delete Role' button."""
        if not self.role_panels:
            return
        names = [self._role_label(rp, i) for i, rp in enumerate(self.role_panels)]
        owner = SwingUtilities.getWindowAncestor(self.main_panel)
        dlg = DeleteRoleDialog(owner, names)
        dlg.setVisible(True)
        if not dlg.confirmed:
            return
        confirm = JOptionPane.showConfirmDialog(
            self.main_panel,
            "Permanently delete %d role(s)? This cannot be undone." % len(dlg.selected_indices),
            "Confirm Delete", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return
        to_delete = [self.role_panels[i] for i in dlg.selected_indices]
        for rp in to_delete:
            if rp in self.role_panels:
                self.role_panels.remove(rp)
                if getattr(self, "_displayed_role_panel", None) is rp:
                    self._displayed_role_panel = None
        if not self.role_panels:
            self._add_role_panel(select=False)
        self._rebuild_role_combo(select_panel=self.role_panels[0])
        JOptionPane.showMessageDialog(self.main_panel, "Deleted %d role(s)." % len(to_delete))

    def _open_delete_item_dialog(self):
        """'🗑 Delete Header/Param From ALL Roles...' — removes a specific
        Header/Parameter row (matched by Type+Key, case-insensitive) from
        every role that has it, in one shot."""
        owner = SwingUtilities.getWindowAncestor(self.main_panel)
        dlg = DeleteItemDialog(owner)
        dlg.setVisible(True)
        if not dlg.confirmed:
            return
        key_l = dlg.key.strip().lower()
        rows_removed = 0
        roles_touched = 0
        for rp in self.role_panels:
            rows_to_remove = []
            for r in range(rp.itemsModel.getRowCount()):
                rt = str(rp.itemsModel.getValueAt(r, 0) or "Header").strip()
                rk = str(rp.itemsModel.getValueAt(r, 1) or "").strip().lower()
                if rt == dlg.item_type and rk == key_l:
                    rows_to_remove.append(r)
            if rows_to_remove:
                for r in sorted(rows_to_remove, reverse=True):
                    rp.itemsModel.removeRow(r)
                rp._update_table_size()
                rp._repaint_items_table()
                rows_removed += len(rows_to_remove)
                roles_touched += 1
        JOptionPane.showMessageDialog(self.main_panel,
            "Removed '%s' (%s): %d row(s) across %d role(s)." %
            (dlg.key, dlg.item_type, rows_removed, roles_touched))

    def _ensure_item_key_on_role(self, rp, item_type, key):
        """Make sure role rp has a (item_type, key) row - case-insensitive
        key match. Never touches an existing row's Value. If the row
        doesn't exist yet it's added with a BLANK value."""
        key_l = key.strip().lower()
        for r in range(rp.itemsModel.getRowCount()):
            rt = str(rp.itemsModel.getValueAt(r, 0) or "Header").strip()
            rk = str(rp.itemsModel.getValueAt(r, 1) or "").strip().lower()
            if rt == item_type and rk == key_l:
                return
        rp.itemsModel.addRow([item_type, key, u""])
        rp._update_table_size()

    def open_apply_to_roles_dialog(self, source_rp, item_type, key, source_container):
        """'⚡ Apply Item To ALL Roles' — checklist of every role; picks which
        ones get this Type+Key added (Value is never copied). If the source
        role's Container has a saved regex fingerprint for this Key, that
        fingerprint is copied too, scoped to each target role's own
        Container."""
        names = [self._role_label(rp, i) for i, rp in enumerate(self.role_panels)]
        exclude_idx = self.role_panels.index(source_rp) if source_rp in self.role_panels else None
        regex_info = self.get_grep_pattern(item_type, key, source_container)

        owner = SwingUtilities.getWindowAncestor(self.main_panel)
        dlg = ApplyToRolesDialog(owner, names, item_type, key,
                                  exclude_index=exclude_idx, has_regex=bool(regex_info))
        dlg.setVisible(True)

        if not dlg.confirmed:
            return

        count = 0
        for i in dlg.selected_indices:
            rp = self.role_panels[i]
            self._ensure_item_key_on_role(rp, item_type, key)
            if regex_info:
                self.save_grep_pattern(item_type, key,
                                        regex_info["regex"],
                                        regex_info.get("prefix", u""),
                                        regex_info.get("suffix", u""),
                                        container=rp.get_container_name())
            rp._repaint_items_table()
            count += 1

        JOptionPane.showMessageDialog(self.main_panel,
            "Applied Key '%s' to %d role(s). Value was not copied." % (key, count))

    def bulk_apply_endpoint_to_all_roles(self, endpoint_value, exclude_rp=None):
        count = 0
        for rp in self.role_panels:
            if rp is exclude_rp:
                continue
            rp.endpointField.setText(endpoint_value)
            count += 1
        return count

    def _combined_text(self, headers, body_bytes):
        """Flattens a parsed headers-list + body into one searchable block of
        text, the same shape a person would get pasting raw traffic into the
        Grab Value dialog - so a saved fingerprint regex matches either way."""
        try:
            body_str = self.helpers.bytesToString(body_bytes) if body_bytes else u""
        except:
            body_str = u""
        head_str = u"\n".join(_u(h) for h in (headers or []))
        return head_str + u"\n\n" + _u(body_str)

    def _grep_pattern_key(self, item_type, key, container):
        container_key = _norm_container_name(container)
        return u"%s::%s::%s" % (container_key, item_type, key.strip().lower())

    def has_grep_pattern(self, item_type, key, container=u""):
        if not key:
            return False
        return self._grep_pattern_key(item_type, key, container) in self._grep_patterns

    def get_grep_pattern(self, item_type, key, container=u""):
        if not key:
            return None
        return self._grep_patterns.get(self._grep_pattern_key(item_type, key, container))

    def save_grep_pattern(self, item_type, key, regex, prefix=u"", suffix=u"", container=u""):
        pk = self._grep_pattern_key(item_type, key, container)
        self._grep_patterns[pk] = {"regex": regex, "prefix": prefix, "suffix": suffix}
        self._saveGrepPatterns()

    def _extract_via_grep(self, item_type, key, text, container=u""):
        info = self.get_grep_pattern(item_type, key, container)
        if not info:
            return None
        try:
            m = re.search(info["regex"], text, re.DOTALL)
            if m:
                return m.group(1)
        except Exception as ex:
            print("[Grep Extract Error] " + str(ex))
        return None

    def _saveGrepPatterns(self):
        try:
            with open(GREP_FILE, "w") as f:
                json.dump(self._grep_patterns, f, indent=2)
        except Exception as e:
            print("[Grep Save Error] " + str(e))

    def _loadGrepPatterns(self):
        try:
            if not os.path.exists(GREP_FILE):
                return
            with open(GREP_FILE, "r") as f:
                self._grep_patterns = json.load(f)
        except Exception as e:
            print("[Grep Load Error] " + str(e))

    def _on_export(self):
        chooser = JFileChooser()
        chooser.setSelectedFile(File("pr0f_headerswitch_config.json"))
        ret = chooser.showSaveDialog(self.main_panel)
        if ret != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".json"):
            path += ".json"

        roles = [rp.get_entry() for rp in self.role_panels]

        relevant_grep = {}
        for rp in self.role_panels:
            container = rp.get_container_name()
            for r in range(rp.itemsModel.getRowCount()):
                t = str(rp.itemsModel.getValueAt(r, 0) or "Header").strip()
                k = str(rp.itemsModel.getValueAt(r, 1) or "").strip()
                if not k:
                    continue
                info = self.get_grep_pattern(t, k, container)
                if info:
                    relevant_grep[self._grep_pattern_key(t, k, container)] = info

        data = {"roles": roles, "grep_patterns": relevant_grep}
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            JOptionPane.showMessageDialog(self.main_panel,
                "Exported %d role(s) to:\n%s" % (len(roles), path))
        except Exception as ex:
            JOptionPane.showMessageDialog(self.main_panel, "Export failed: %s" % str(ex))

    def _on_import(self):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self.main_panel)
        if ret != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception as ex:
            JOptionPane.showMessageDialog(self.main_panel, "Import failed: %s" % str(ex))
            return

        entries = data.get("roles", []) if isinstance(data, dict) else []
        if not entries:
            JOptionPane.showMessageDialog(self.main_panel, "No roles found in that file.")
            return

        for entry in entries:
            self._add_role_panel(entry.get("role", ""), entry.get("color"), entry.get("items", []),
                                  entry.get("container", ""), entry.get("endpoint", ""), select=False)

        grep = data.get("grep_patterns", {}) if isinstance(data, dict) else {}
        if isinstance(grep, dict) and grep:
            self._grep_patterns.update(grep)
            self._saveGrepPatterns()

        if self.role_panels:
            self._rebuild_role_combo(select_panel=self.role_panels[-1])
        JOptionPane.showMessageDialog(self.main_panel,
            "Imported %d role(s)%s." %
            (len(entries), (" + %d saved value(s)" % len(grep)) if grep else ""))

    def _build_results_tab(self):
        sz = self._current_font_size
        self._results_outer = JPanel(BorderLayout())
        self._results_outer.setBackground(Color(28, 28, 28))

        topBar = JPanel(BorderLayout())
        topBar.setBackground(Color(20, 20, 20))

        self.lblStatus = JLabel("  Ready")
        self.lblStatus.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.lblStatus.setForeground(Color(150, 150, 150))

        def mkbtn(txt, bg, fn):
            b = JButton(txt)
            b.setBackground(bg)
            b.setForeground(Color.WHITE)
            b.setFont(Font("Monospaced", Font.BOLD, sz))
            b.setFocusPainted(False)
            b.addActionListener(lambda e: fn())
            return b

        btnBar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        btnBar.setBackground(Color(20, 20, 20))
        btnBar.add(mkbtn("Clear All Groups", Color(140, 40, 40), self._clearAllBatches))
        btnBar.add(mkbtn("Delete Current Group", Color(150, 90, 40), self._deleteCurrentGroup))
        btnBar.add(mkbtn("\U0001F441 Filter Columns...", Color(70, 110, 150), self._open_column_filter))

        lblSort = JLabel("  Sort:")
        lblSort.setForeground(Color(190, 190, 190))
        lblSort.setFont(Font("Monospaced", Font.PLAIN, sz))
        btnBar.add(lblSort)
        self.sortCombo = JComboBox(["Newest First", "ID \u2191", "ID \u2193", "Size \u2191", "Size \u2193", "Matches \u2713 Top"])
        self.sortCombo.setFont(Font("Monospaced", Font.PLAIN, sz))
        def _onSortChange(e):
            idx = self.sortCombo.getSelectedIndex()
            mapping = [None, ("id", "asc"), ("id", "desc"), ("size", "asc"), ("size", "desc"), ("match", "desc")]
            self._sort_mode = mapping[idx] if 0 <= idx < len(mapping) else None
            self._resort_all_batches()
        self.sortCombo.addActionListener(_onSortChange)
        btnBar.add(self.sortCombo)

        lblSearch = JLabel("  Search:")
        lblSearch.setForeground(Color(190, 190, 190))
        lblSearch.setFont(Font("Monospaced", Font.PLAIN, sz))
        btnBar.add(lblSearch)

        
        self.comboSearchScope = JComboBox(["Both", "Request", "Response"])
        self.comboSearchScope.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.comboSearchScope.setSelectedItem(self._search_scope)
        def _onScopeChange(e):
            self._search_scope = str(self.comboSearchScope.getSelectedItem())
            self._resort_all_batches()
        self.comboSearchScope.addActionListener(_onScopeChange)
        btnBar.add(self.comboSearchScope)

        self.fldResultSearch = JTextField(self._search_text, 20)
        self.fldResultSearch.setBackground(Color(45, 45, 45))
        self.fldResultSearch.setForeground(Color(220, 220, 220))
        self.fldResultSearch.setCaretColor(Color(255, 180, 0))
        self.fldResultSearch.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.fldResultSearch.setToolTipText(
            "Marks each row with a \u2713/\u2717 in the 'Match' column (enable it via "
            "'Filter Columns...') depending on whether this text appears in that "
            "row's request/response. This text stays here until YOU clear it - "
            "opening a new Group never resets it.")
        outer_self = self
        class ResultSearchListener(DocumentListener):
            def insertUpdate(self, e): outer_self._on_search_changed()
            def removeUpdate(self, e): outer_self._on_search_changed()
            def changedUpdate(self, e): outer_self._on_search_changed()
        self.fldResultSearch.getDocument().addDocumentListener(ResultSearchListener())
        btnBar.add(self.fldResultSearch)

        btnBar.add(self.lblStatus)
        topBar.add(btnBar, BorderLayout.WEST)
        self._results_outer.add(topBar, BorderLayout.NORTH)

        self._batch_tabs = JTabbedPane()
        self._batch_tabs.setFont(Font("Monospaced", Font.BOLD, sz))
        self._batch_tabs.setBackground(Color(28, 28, 28))
        self._batch_tabs.setForeground(Color(255, 180, 0))
        self.reqEditor  = self.callbacks.createMessageEditor(self, False)
        self.respEditor = self.callbacks.createMessageEditor(self, False)

        rrSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                             self.reqEditor.getComponent(),
                             self.respEditor.getComponent())
        rrSplit.setResizeWeight(0.5)
        rrSplit.setOneTouchExpandable(True)

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._batch_tabs, rrSplit)
        mainSplit.setResizeWeight(0.35)
        mainSplit.setOneTouchExpandable(True)

        self._results_outer.add(mainSplit, BorderLayout.CENTER)
        self.tabs.addTab("Results", self._results_outer)

    def get_visible_columns(self):
        return list(self._visible_columns)

    def get_sort_mode(self):
        return self._sort_mode

    def get_search_text(self):
        return self._search_text

    def result_matches_search(self, result, text):
        if not text:
            return True
        text_l = text.lower()
        try:
            req_s = self.helpers.bytesToString(result["request"]) if result.get("request") else u""
        except:
            req_s = u""
        try:
            resp_s = self.helpers.bytesToString(result["response"]) if result.get("response") else u""
        except:
            resp_s = u""
            
        scope = getattr(self, "_search_scope", "Both")
        role_s = _u(result.get("role", "")).lower()
        
        if scope == "Request":
            target = role_s + u" " + _u(req_s).lower()
        elif scope == "Response":
            target = role_s + u" " + _u(resp_s).lower()
        else: 
            target = role_s + u" " + _u(req_s).lower() + u" " + _u(resp_s).lower()
            
        return text_l in target

    def _on_search_changed(self):
        self._search_text = self.fldResultSearch.getText()
        self._resort_all_batches()

    def _resort_all_batches(self):
        for bp in self._batch_panels:
            bp.refresh_table()

    def _open_column_filter(self):
        owner = SwingUtilities.getWindowAncestor(self.main_panel)
        dlg = ColumnFilterDialog(owner, ALL_RESULT_COLUMNS, self._visible_columns)
        dlg.setVisible(True)
        if not dlg.confirmed:
            return
        self._visible_columns = dlg.selected
        for bp in self._batch_panels:
            bp._apply_visible_columns(self._visible_columns)
        self._saveSettings()

    def _display_result(self, result):
        """Called by whichever BatchPanel's table selection changed - loads
        that row into the shared request/response editors."""
        self.current_display = result
        self.reqEditor.setMessage(result["request"], True)
        resp = result["response"]
        self.respEditor.setMessage(resp if resp else b"", False)

    def _build_history_tab(self):
        sz = self._current_font_size
        outer = JPanel(BorderLayout())
        outer.setBackground(Color(28, 28, 28))

        searchBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        searchBar.setBackground(Color(20, 20, 20))
        searchBar.add(JLabel("  Search:"))
        self.fldHistSearch = JTextField(30)
        self.fldHistSearch.setBackground(Color(45, 45, 45))
        self.fldHistSearch.setForeground(Color(220, 220, 220))
        self.fldHistSearch.setCaretColor(Color(255, 180, 0))
        self.fldHistSearch.setFont(Font("Monospaced", Font.PLAIN, sz))
        searchBar.add(self.fldHistSearch)

        def mkbtn(txt, bg, fn):
            b = JButton(txt)
            b.setBackground(bg)
            b.setForeground(Color.WHITE)
            b.setFont(Font("Monospaced", Font.BOLD, sz))
            b.setFocusPainted(False)
            b.addActionListener(lambda e: fn())
            return b

        searchBar.add(mkbtn("Resend Selected (All Roles)", Color(60, 100, 160), self._resendSelectedHistory))
        searchBar.add(mkbtn("Delete Selected", Color(140, 40, 40), self._deleteSelectedHistory))
        searchBar.add(mkbtn("Clear History", Color(100, 40, 40), self._clearHistory))
        outer.add(searchBar, BorderLayout.NORTH)

        self.histModel = DefaultTableModel(["ID", "Method", "Path", "Size", "Time"], 0)
        self.histTable = JTable(self.histModel)
        self.histTable.setBackground(Color(28, 28, 28))
        self.histTable.setForeground(Color(220, 220, 220))
        self.histTable.setSelectionBackground(Color(80, 60, 20))
        self.histTable.setGridColor(Color(15, 15, 15))
        self.histTable.setFont(Font("Monospaced", Font.PLAIN, sz))
        self.histTable.setRowHeight(sz + 14)
        self.histTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.histTable.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.histTable.getColumnModel().getColumn(1).setPreferredWidth(70)
        self.histTable.getColumnModel().getColumn(2).setPreferredWidth(350)
        self.histTable.getColumnModel().getColumn(3).setPreferredWidth(70)
        self.histTable.getColumnModel().getColumn(4).setPreferredWidth(160)

        header = self.histTable.getTableHeader()
        header.setBackground(Color(20, 20, 20))
        header.setForeground(Color(255, 180, 0))
        header.setFont(Font("Monospaced", Font.BOLD, sz))

        self._histSorter = TableRowSorter(self.histModel)
        self.histTable.setRowSorter(self._histSorter)
        self.histTable.getSelectionModel().addListSelectionListener(self._onHistRowSelect)

        outer_self = self
        class HistSearchListener(DocumentListener):
            def insertUpdate(self, e): outer_self._applyHistFilter()
            def removeUpdate(self, e): outer_self._applyHistFilter()
            def changedUpdate(self, e): outer_self._applyHistFilter()
        self.fldHistSearch.getDocument().addDocumentListener(HistSearchListener())

        histScroll = JScrollPane(self.histTable)
        histScroll.setPreferredSize(Dimension(900, 220))

        class HistMsgCtrl(IMessageEditorController):
            def __init__(self, ext): self._ext = ext
            def getHttpService(self):
                e = self._ext.current_hist_entry
                if e:
                    return self._ext.helpers.buildHttpService(e["host"], e["port"], e["protocol"] == "https")
                return None
            def getRequest(self):
                e = self._ext.current_hist_entry
                return e["request"] if e else None
            def getResponse(self):
                return None

        self._histMsgCtrl = HistMsgCtrl(self)
        self.histReqEditor = self.callbacks.createMessageEditor(self._histMsgCtrl, False)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, histScroll, self.histReqEditor.getComponent())
        split.setResizeWeight(0.4)
        split.setOneTouchExpandable(True)
        outer.add(split, BorderLayout.CENTER)

        self.tabs.addTab("History", outer)

    def _onHistRowSelect(self, event):
        row = self.histTable.getSelectedRow()
        if row < 0:
            return
        mr = self.histTable.convertRowIndexToModel(row)
        try:
            row_id = int(str(self.histModel.getValueAt(mr, 0)))
        except:
            return
        for e in self.history:
            if e["id"] == row_id:
                self.current_hist_entry = e
                self.histReqEditor.setMessage(e["request"], True)
                break

    def _applyHistFilter(self):
        text = self.fldHistSearch.getText().strip()
        try:
            if not text:
                self._histSorter.setRowFilter(None)
            else:
                self._histSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
        except:
            pass

    def _colors_map(self):
        m = {}
        for rp in self.role_panels:
            name = rp.get_role_name()
            if name:
                m[name] = rp.color_hex
        return m

    def _on_batch_delete_ids(self, ids_to_del):
        self.results = [r for r in self.results if r["id"] not in ids_to_del]
        self._saveResults()

    def _new_batch_panel(self):
        batch_id = self._next_batch[0]
        self._next_batch[0] += 1

        panel = BatchPanel(
            batch_id,
            self._colors_map,
            self._current_font_size,
            self._display_result,
            self._on_batch_delete_ids,
            self
        )
        self._batch_panels.append(panel)
        self._batch_tabs.addTab("Group %d" % batch_id, panel)
        self._batch_tabs.setSelectedIndex(self._batch_tabs.getTabCount() - 1)
        self.tabs.setSelectedIndex(1)
        return panel

    def _deleteCurrentGroup(self):
        """'Delete Current Group' — removes only the currently-open Group
        tab and its results, unlike 'Clear All Groups' which wipes every
        group."""
        idx = self._batch_tabs.getSelectedIndex()
        if idx < 0 or idx >= len(self._batch_panels):
            JOptionPane.showMessageDialog(self.main_panel, "No group is currently open.")
            return
        panel = self._batch_panels[idx]
        confirm = JOptionPane.showConfirmDialog(
            self.main_panel,
            "Delete Group %d and all its results? This cannot be undone." % panel.batch_id,
            "Confirm", JOptionPane.YES_NO_OPTION)
        if confirm != JOptionPane.YES_OPTION:
            return
        batch_id = panel.batch_id
        self.results = [r for r in self.results if r.get("batch_id") != batch_id]
        self._batch_panels.pop(idx)
        self._batch_tabs.remove(idx)
        self._saveResults()
        self._setStatus("Group %d deleted" % batch_id, Color(150, 150, 150))
    def _config_to_role_entries(self, cfg):
        """Backward compatible: supports new {'roles':[...]} and the old
        fixed-row format ({'row_0': {...}, ...})."""
        if not cfg:
            return []
        if "roles" in cfg:
            return cfg["roles"]
        entries = []
        i = 0
        while ("row_%d" % i) in cfg:
            v = cfg["row_%d" % i]
            role = v.get("role", "").strip()
            i += 1
            if not role:
                continue
            items = []
            for slot in (1, 2, 3):
                t = v.get("type_%d" % slot, "Header")
                k = v.get("key_%d" % slot, v.get("header_%d" % slot, ""))
                val = v.get("val_%d" % slot, v.get("value_%d" % slot, ""))
                if k:
                    items.append({"type": t, "key": k, "val": val})
            entries.append({"role": role, "color": v.get("color"), "items": items, "container": "", "endpoint": ""})
        return entries

    def _on_save(self):
        roles = []
        for rp in self.role_panels:
            entry = rp.get_entry()
            roles.append(entry)
        self.config = {"roles": roles}
        self.callbacks.saveExtensionSetting("RoleSwitch_cfg", json.dumps(self.config))
        self._saveSettings()
        JOptionPane.showMessageDialog(self.main_panel, "Saved.")

    def _on_load(self):
        self.config = self.load_config()
        self.role_panels = []
        self._displayed_role_panel = None
        entries = self._config_to_role_entries(self.config)
        for entry in entries:
            self._add_role_panel(entry.get("role", ""), entry.get("color"), entry.get("items", []),
                                  entry.get("container", ""), entry.get("endpoint", ""), select=False)
        if not self.role_panels:
            self._add_role_panel(select=False)
        self._rebuild_role_combo(select_panel=self.role_panels[0])
        JOptionPane.showMessageDialog(self.main_panel, "Loaded.")

    def _on_clear(self):
        self.role_panels = []
        self._displayed_role_panel = None
        self._add_role_panel(select=False)
        self._rebuild_role_combo(select_panel=self.role_panels[0])

    def load_config(self):
        try:
            s = self.callbacks.loadExtensionSetting("RoleSwitch_cfg")
            if s:
                return json.loads(s)
        except:
            pass
        return {}

    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return None

        items = []

        mi1 = JMenuItem("Send ALL Roles With Method")
        class H1(ActionListener):
            def __init__(self, outer, msgs): self.outer = outer; self.msgs = msgs
            def actionPerformed(self, e):
                msgs = self.msgs
                self.outer._enqueue_job(lambda: [self.outer.send_roles_only_to_repeater(m) for m in msgs])
        mi1.addActionListener(H1(self, list(msgs)))
        items.append(mi1)

        mi2 = JMenuItem("Send ALL Roles only")
        class H2(ActionListener):
            def __init__(self, outer, msgs): self.outer = outer; self.msgs = msgs
            def actionPerformed(self, e):
                msgs = self.msgs
                self.outer._enqueue_job(lambda: [self.outer.send_all_roles_to_repeater(m) for m in msgs])
        mi2.addActionListener(H2(self, list(msgs)))
        items.append(mi2)

        items.append(JMenuItem("────────────────"))

        for rp in self.role_panels:
            entry = rp.get_entry()
            if not entry["role"]:
                continue
            mi = JMenuItem(entry["role"])
            class SH(ActionListener):
                def __init__(self, ent, msgs, outer): self.ent = ent; self.msgs = msgs; self.outer = outer
                def actionPerformed(self, e):
                    for m in self.msgs:
                        self.outer.apply_role_to_message(m, self.ent)
            mi.addActionListener(SH(entry, list(msgs), self))
            items.append(mi)

        return items

    def _get_role_entries(self):
        return [rp.get_entry() for rp in self.role_panels]

    def _apply_header_logic(self, headers, header_raw, header_value):
        if not header_raw:
            return headers, False
        header_name   = header_raw
        header_prefix = None
        if ":" in header_raw:
            parts = header_raw.split(":", 1)
            header_name   = parts[0].strip()
            header_prefix = parts[1].strip() or None
        replaced    = False
        new_headers = []
        for h in headers:
            if ":" in h:
                name_part = h.split(":", 1)[0].strip()
                if name_part.lower() == header_name.lower():
                    if header_prefix:
                        new_headers.append("%s: %s %s" % (name_part, header_prefix, header_value))
                    else:
                        new_headers.append("%s: %s" % (name_part, header_value))
                    replaced = True
                    continue
            new_headers.append(h)
        if not replaced and header_value:
            if header_prefix:
                new_headers.append("%s: %s %s" % (header_name, header_prefix, header_value))
            else:
                new_headers.append("%s: %s" % (header_name, header_value))
        return new_headers, True

    def _apply_param_logic(self, headers, body_bytes, key, value):
        if not key:
            return headers, body_bytes

        content_type = ""
        for h in headers:
            if ":" in h and h.split(":", 1)[0].strip().lower() == "content-type":
                content_type = h.split(":", 1)[1].strip().lower()
                break

        body_str = ""
        if body_bytes:
            try:
                body_str = self.helpers.bytesToString(body_bytes)
            except:
                body_str = ""

        body_found = False
        new_body_str = body_str
        if "json" in content_type and body_str.strip():
            pattern = re.compile(
                r'(["\']' + re.escape(key) + r'["\']\s*:\s*)'
                r'("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
            )
            replacement_value = json.dumps(value)
            def _json_repl(m):
                return m.group(1) + replacement_value
            new_str, n_subs = pattern.subn(_json_repl, body_str)
            if n_subs > 0:
                new_body_str = new_str
                body_found = True
        elif body_str:
            params = body_str.split("&")
            new_params = []
            for p in params:
                if "=" in p:
                    k = p.split("=", 1)[0]
                    if k == key:
                        new_params.append("%s=%s" % (key, value))
                        body_found = True
                        continue
                new_params.append(p)
            if body_found:
                new_body_str = "&".join(new_params)

        new_body_bytes = self.helpers.stringToBytes(new_body_str) if body_found else body_bytes

        new_headers = list(headers)
        if new_headers:
            first_line = new_headers[0]
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method   = parts[0]
                url_part = parts[1]
                rest     = " ".join(parts[2:])
                if "?" in url_part:
                    path, qs = url_part.split("?", 1)
                    qparams = qs.split("&")
                    found_q = False
                    new_q = []
                    for p in qparams:
                        if "=" in p:
                            k = p.split("=", 1)[0]
                            if k == key:
                                new_q.append("%s=%s" % (key, value))
                                found_q = True
                                continue
                        new_q.append(p)
                    if found_q:
                        new_url = path + "?" + "&".join(new_q)
                        new_headers[0] = "%s %s %s" % (method, new_url, rest)

        return new_headers, new_body_bytes

    def _apply_items(self, headers, body, entry):
        for item in entry.get("items", []):
            t   = item.get("type", "Header")
            key = item.get("key", "")
            val = item.get("val", "")
            if not key:
                continue
            if t == "Parameter":
                headers, body = self._apply_param_logic(headers, body, key, val)
            else:
                headers, _ = self._apply_header_logic(headers, key, val)
        return headers, body

    def apply_role_to_message(self, messageInfo, role_entry):
        request  = messageInfo.getRequest()
        analyzed = self.helpers.analyzeRequest(request)
        headers  = list(analyzed.getHeaders())
        body     = request[analyzed.getBodyOffset():]
        headers, body = self._apply_items(headers, body, role_entry)
        java_headers = [String(h) for h in headers]
        messageInfo.setRequest(self.helpers.buildHttpMessage(java_headers, body))

    def _extract_header_value(self, headers, header_raw):
        header_name   = header_raw
        header_prefix = None
        if ":" in header_raw:
            parts = header_raw.split(":", 1)
            header_name   = parts[0].strip()
            header_prefix = parts[1].strip()
        for h in headers:
            if ":" in h:
                name_part = h.split(":", 1)[0].strip()
                if name_part.lower() == header_name.lower():
                    remainder = h.split(":", 1)[1].strip()
                    if header_prefix and remainder.lower().startswith(header_prefix.lower()):
                        return remainder[len(header_prefix):].strip()
                    elif not header_prefix:
                        return remainder
        return None

    def _extract_html_hidden_value(self, body_str, key):
        """Finds <input name="KEY" ... value="VALUE" ...> (attributes in any
        order, single or double quotes) - covers anti-CSRF tokens embedded as
        hidden form fields, e.g. ASP.NET's __RequestVerificationToken:
        <input name="__RequestVerificationToken" type="hidden" value="..."/>
        """
        if not body_str:
            return None
        for m in re.finditer(r'<input\b([^>]*)>', body_str, re.IGNORECASE):
            tag_attrs = m.group(1)
            if not re.search(r'\bname\s*=\s*["\']' + re.escape(key) + r'["\']', tag_attrs, re.IGNORECASE):
                continue
            val_m = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
            if val_m:
                return val_m.group(1)
        return None

    def _extract_html_meta_value(self, body_str, key):
        """Finds <meta name="KEY" content="VALUE"> (attributes in any order) -
        a very common place frameworks stash a CSRF token, e.g.
        <meta name="csrf-token" content="...">"""
        if not body_str:
            return None
        for m in re.finditer(r'<meta\b([^>]*)>', body_str, re.IGNORECASE):
            tag_attrs = m.group(1)
            if not re.search(r'\bname\s*=\s*["\']' + re.escape(key) + r'["\']', tag_attrs, re.IGNORECASE):
                continue
            val_m = re.search(r'\bcontent\s*=\s*["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)
            if val_m:
                return val_m.group(1)
        return None

    def _extract_body_value(self, body_bytes, content_type, key):
        """Tries every known way a value shows up in a body, in order, and
        returns the first hit. Deliberately does NOT gate any of these on the
        declared Content-Type header - servers routinely mislabel bodies (a
        JSON blob embedded inside an HTML page's <script> tag under a
        text/html Content-Type is common), so every pattern is always tried."""
        body_str = ""
        if body_bytes:
            try:
                body_str = self.helpers.bytesToString(body_bytes)
            except:
                body_str = ""
        if not body_str:
            return None

        esc = re.escape(key)

        m = re.search(
            r'["\']' + esc + r'["\']\s*:\s*'
            r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|-?\d+(?:\.\d+)?|true|false|null)',
            body_str
        )
        if m:
            raw = m.group(1)
            try:
                return json.loads(raw) if raw[:1] != "'" else raw[1:-1]
            except:
                return raw.strip('"\'')

        html_val = self._extract_html_hidden_value(body_str, key)
        if html_val is not None:
            return html_val

        meta_val = self._extract_html_meta_value(body_str, key)
        if meta_val is not None:
            return meta_val


        m = re.search(esc + r'\s*[:=]\s*["\']([^"\']*)["\']', body_str)
        if m:
            return m.group(1)

        for p in body_str.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                if k == key:
                    return v
        return None

    def _extract_param_value(self, headers, body_bytes, key):
        """Extract a param from a REQUEST: checks the URL query string first,
        then the body (JSON, HTML, or form-encoded - see _extract_body_value)."""
        content_type = ""
        for h in headers:
            if ":" in h and h.split(":", 1)[0].strip().lower() == "content-type":
                content_type = h.split(":", 1)[1].strip().lower()
                break

        if headers:
            first_line = headers[0]
            parts = first_line.split(" ")
            if len(parts) >= 2 and "?" in parts[1]:
                qs = parts[1].split("?", 1)[1]
                for p in qs.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        if k == key:
                            return v

        return self._extract_body_value(body_bytes, content_type, key)

    def _extract_response_param_value(self, resp_headers, resp_body_bytes, key):
        """Extract a param from a RESPONSE body (JSON, HTML, or form-encoded).
        Used as a fallback for tokens (e.g. CSRF) that only ever come back in
        the response and are never echoed in a later request's own body/URL."""
        content_type = ""
        for h in resp_headers:
            if ":" in h and h.split(":", 1)[0].strip().lower() == "content-type":
                content_type = h.split(":", 1)[1].strip().lower()
                break
        return self._extract_body_value(resp_body_bytes, content_type, key)

    def _parse_endpoint(self, s):
        """Parses the role's 'Endpoint' field. Accepts 'METHOD /path' (e.g.
        'POST /graph') or just '/path' (matches any method). Returns
        (method_or_None, path_or_None). Empty/blank -> (None, None), meaning
        "no restriction - search all captured traffic for this container"."""
        s = (s or "").strip()
        if not s:
            return None, None
        parts = s.split(None, 1)
        known_methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        if len(parts) == 2 and parts[0].upper() in known_methods:
            return parts[0].upper(), parts[1].strip()
        return None, s

    def _request_matches_endpoint(self, headers, method, path):
        """method/path as returned by _parse_endpoint; both None means match
        anything. Path is compared exactly against the request's path (query
        string ignored), never as a prefix/substring, so 'POST /graph' can't
        accidentally match 'POST /graphql' or similar."""
        if method is None and path is None:
            return True
        if not headers:
            return False
        first_line = headers[0]
        parts = first_line.split(" ")
        if len(parts) < 2:
            return False
        req_method = parts[0].upper()
        req_path   = parts[1].split("?", 1)[0]
        if method is not None and req_method != method:
            return False
        if path is not None and req_path != path:
            return False
        return True

    def update_role_from_container(self, rp, notify=False):
        container = rp.get_container_name()
        if not container:
            if notify:
                JOptionPane.showMessageDialog(self.main_panel,
                    "Set the Container name for this role first (must match the "
                    "Firefox container name exactly).")
            return False

        hist = self._container_history.get(_norm_container_name(container))
        if not hist:
            if notify:
                JOptionPane.showMessageDialog(self.main_panel,
                    "No captured traffic yet for container '%s'.\n\n"
                    "Browse a request through Burp Proxy from that Firefox "
                    "container first (with the companion extension's header "
                    "injection enabled) so RoleSwitch can see it." % container)
            return False

        parsed = []
        for entry in hist:
            try:
                req_bytes = bytes(entry["request"])
                req_analyzed = self.helpers.analyzeRequest(req_bytes)
                req_headers  = list(req_analyzed.getHeaders())
                req_body     = bytearray(entry["request"])[req_analyzed.getBodyOffset():]

                resp_headers, resp_body = [], None
                resp_raw = entry.get("response")
                if resp_raw:
                    try:
                        resp_bytes    = bytes(resp_raw)
                        resp_analyzed = self.helpers.analyzeResponse(resp_bytes)
                        resp_headers  = list(resp_analyzed.getHeaders())
                        resp_body     = bytearray(resp_raw)[resp_analyzed.getBodyOffset():]
                    except Exception as ex:
                        print("[Update From Container Response Parse Error] " + str(ex))

                parsed.append({
                    "headers": req_headers, "body": req_body,
                    "resp_headers": resp_headers, "resp_body": resp_body,
                    "time": entry.get("time", "")
                })
            except Exception as ex:
                print("[Update From Container Parse Error] " + str(ex))

        if not parsed:
            if notify:
                JOptionPane.showMessageDialog(self.main_panel,
                    "Captured traffic for '%s' exists but couldn't be parsed." % container)
            return False
        ep_method, ep_path = self._parse_endpoint(rp.get_endpoint())
        if ep_method is not None or ep_path is not None:
            endpoint_parsed = [p for p in parsed if self._request_matches_endpoint(p["headers"], ep_method, ep_path)]
            if not endpoint_parsed:
                if notify:
                    JOptionPane.showMessageDialog(self.main_panel,
                        "Captured %d request(s) for container '%s', but none match "
                        "the configured Endpoint '%s'.\n\n"
                        "Browse/trigger that exact request through Burp Proxy from "
                        "that container first." % (len(parsed), container, rp.get_endpoint()))
                return False
            parsed = endpoint_parsed

        updated_keys = []
        missing_keys = []
        for r in range(rp.itemsModel.getRowCount()):
            t   = str(rp.itemsModel.getValueAt(r, 0) or "Header").strip()
            key = str(rp.itemsModel.getValueAt(r, 1) or "").strip()
            if not key:
                continue

            found_val = None
            found_in  = None
            for p in parsed:
                v = None
                resp_text = self._combined_text(p.get("resp_headers"), p.get("resp_body"))
                v = self._extract_via_grep(t, key, resp_text, container=container)
                if v is not None:
                    found_in = "response (grep)"
                else:
                    req_text = self._combined_text(p["headers"], p["body"])
                    v = self._extract_via_grep(t, key, req_text, container=container)
                    if v is not None:
                        found_in = "request (grep)"

                if v is None:
                    if t == "Parameter":
                        v = self._extract_param_value(p["headers"], p["body"], key)
                        if v is None and p.get("resp_body") is not None:
                            v = self._extract_response_param_value(p["resp_headers"], p["resp_body"], key)
                            if v is not None:
                                found_in = "response"
                        elif v is not None:
                            found_in = "request"
                    else:
                        v = self._extract_header_value(p["headers"], key)
                        if v is None and p.get("resp_headers"):
                            v = self._extract_header_value(p["resp_headers"], key)
                            if v is not None:
                                found_in = "response"
                        elif v is not None:
                            found_in = "request"

                if v is not None:
                    found_val = v
                    break

            if found_val is not None:
                rp.itemsModel.setValueAt(str(found_val), r, 2)
                if found_in and found_in != "request":
                    updated_keys.append("%s (%s)" % (key, found_in))
                else:
                    updated_keys.append(key)
            else:
                missing_keys.append(key)

        if notify:
            scope = ("endpoint '%s'" % rp.get_endpoint()) if (ep_method is not None or ep_path is not None) \
                    else "all captured traffic"
            msg_lines = [
                "Role '%s' — searched %d request(s) (%s) for container '%s'." %
                (rp.get_role_name(), len(parsed), scope, container)
            ]
            if updated_keys:
                msg_lines.append("Updated: " + ", ".join(updated_keys))
            if missing_keys:
                msg_lines.append("Not found in any matching request: " + ", ".join(missing_keys))
            if not updated_keys and not missing_keys:
                msg_lines.append("This role has no Header/Parameter keys configured.")
            JOptionPane.showMessageDialog(self.main_panel, "\n".join(msg_lines))

        return len(updated_keys) > 0

    def update_all_roles_from_containers(self):
        updated, skipped = 0, 0
        for rp in self.role_panels:
            if not rp.get_container_name():
                skipped += 1
                continue
            if self.update_role_from_container(rp, notify=False):
                updated += 1
            else:
                skipped += 1
        JOptionPane.showMessageDialog(self.main_panel,
            "Updated %d role(s). %d role(s) skipped (no container set or no "
            "captured traffic yet)." % (updated, skipped))

    def _fire_roles_concurrently(self, messageInfo, entries, batch_panel):
        entries = [e for e in entries if e.get("role")]
        if not entries:
            return
        try:
            threads = int(str(self.spnThreads.getValue()))
        except:
            threads = 1
        threads = max(1, min(threads, len(entries)))

        from java.util.concurrent import Executors
        pool = Executors.newFixedThreadPool(threads)
        try:
            futures = []
            for entry in entries:
                def _task(entry=entry):
                    self._fire_role(messageInfo, entry, entry["role"], batch_panel)
                futures.append(pool.submit(_task))
            for f in futures:
                f.get()
        finally:
            pool.shutdown()
        self._saveResults()
    def _fire_role(self, messageInfo, role_entry, label, batch_panel):
        request  = messageInfo.getRequest()
        analyzed = self.helpers.analyzeRequest(messageInfo)
        headers  = list(analyzed.getHeaders())
        body     = request[analyzed.getBodyOffset():]

        headers, body = self._apply_items(headers, body, role_entry)

        java_headers  = [String(h) for h in headers]
        request_bytes = self.helpers.buildHttpMessage(java_headers, body)

        first_line = headers[0] if headers else ""
        fl_parts   = first_line.split(" ")
        method_val = fl_parts[0] if len(fl_parts) > 0 else "?"
        url_val    = fl_parts[1] if len(fl_parts) > 1 else "?"
        params_val = u", ".join(
            u"%s=%s" % (it.get("key", ""), it.get("val", ""))
            for it in role_entry.get("items", [])
            if it.get("type") == "Parameter" and it.get("key")
        )

        service = messageInfo.getHttpService()
        try:
            resp           = self.callbacks.makeHttpRequest(service, request_bytes)
            response_bytes = resp.getResponse()
        except Exception as ex:
            print("[Fire Error] " + str(ex))
            response_bytes = None

        status = "?"
        size   = 0
        if response_bytes:
            ar     = self.helpers.analyzeResponse(response_bytes)
            status = str(ar.getStatusCode())
            size   = len(response_bytes)

        with self._results_lock:
            result_id = self._next_id[0]
            self._next_id[0] += 1

        result = {
            "id":       result_id,
            "batch_id": batch_panel.batch_id,
            "label":    label,
            "role":     role_entry["role"] if "role" in role_entry else label,
            "status":   status,
            "size":     size,
            "host":     service.getHost(),
            "port":     service.getPort(),
            "protocol": service.getProtocol(),
            "time":     cairo_timestamp(),
            "method":   method_val,
            "url":      url_val,
            "params":   params_val,
            "request":  request_bytes,
            "response": response_bytes,
        }
        with self._results_lock:
            self.results.append(result)

        def _ui(r=result, bp=batch_panel):
            bp.add_result(r)
            self._setStatus("Group %d | %s → %s" % (bp.batch_id, r["role"], r["status"]),
                            Color(255, 180, 0))
        SwingUtilities.invokeLater(_ui)

        try:
            rps = float(self.fldRPS.getText().strip())
            if rps > 0:
                import time; time.sleep(1.0 / rps)
        except:
            pass

    def send_all_roles_to_repeater(self, messageInfo):
        """Fire all roles → new Group tab."""
        self._add_history(messageInfo)

        from java.util.concurrent import CountDownLatch
        latch = CountDownLatch(1)
        container = [None]
        def _create():
            container[0] = self._new_batch_panel()
            latch.countDown()
        SwingUtilities.invokeLater(_create)
        latch.await()
        batch_panel = container[0]

        self._fire_roles_concurrently(messageInfo, self._get_role_entries(), batch_panel)

    def send_roles_only_to_repeater(self, messageInfo):
        """Roles + method variants → new Group tab."""
        self._add_history(messageInfo)

        from java.util.concurrent import CountDownLatch
        latch = CountDownLatch(1)
        container = [None]
        def _create():
            container[0] = self._new_batch_panel()
            latch.countDown()
        SwingUtilities.invokeLater(_create)
        latch.await()
        batch_panel = container[0]

        request  = messageInfo.getRequest()
        analyzed = self.helpers.analyzeRequest(messageInfo)
        headers  = list(analyzed.getHeaders())
        body     = request[analyzed.getBodyOffset():]
        service  = messageInfo.getHttpService()

        self._fire_roles_concurrently(messageInfo, self._get_role_entries(), batch_panel)

        original_first_line = headers[0]
        parts = original_first_line.split(" ", 2)
        if len(parts) == 3:
            original_method = parts[0]
            path            = parts[1]
            http_version    = parts[2]
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                if method == original_method:
                    continue
                modified_headers    = list(headers)
                modified_headers[0] = "%s %s %s" % (method, path, http_version)
                java_headers        = [String(h) for h in modified_headers]
                new_request         = self.helpers.buildHttpMessage(java_headers, body)
                label               = "METHOD_" + method
                try:
                    resp           = self.callbacks.makeHttpRequest(service, new_request)
                    response_bytes = resp.getResponse()
                except:
                    response_bytes = None
                status = "?"; size = 0
                if response_bytes:
                    ar = self.helpers.analyzeResponse(response_bytes)
                    status = str(ar.getStatusCode())
                    size   = len(response_bytes)

                with self._results_lock:
                    result_id = self._next_id[0]
                    self._next_id[0] += 1

                result = {
                    "id":       result_id,
                    "batch_id": batch_panel.batch_id,
                    "label":    label,
                    "role":     label,
                    "status":   status,
                    "size":     size,
                    "host":     service.getHost(),
                    "port":     service.getPort(),
                    "protocol": service.getProtocol(),
                    "time":     cairo_timestamp(),
                    "method":   method,
                    "url":      path,
                    "params":   u"",
                    "request":  new_request,
                    "response": response_bytes,
                }
                with self._results_lock:
                    self.results.append(result)

                def _ui(r=result, bp=batch_panel):
                    bp.add_result(r)
                    self._setStatus("Group %d | %s → %s" % (bp.batch_id, r["role"], r["status"]),
                                    Color(255, 180, 0))
                SwingUtilities.invokeLater(_ui)
                self._saveResults()

                try:
                    rps = float(self.fldRPS.getText().strip())
                    if rps > 0:
                        import time; time.sleep(1.0 / rps)
                except:
                    pass

    def _build_signature(self, messageInfo):
        request  = messageInfo.getRequest()
        service  = messageInfo.getHttpService()
        analyzed = self.helpers.analyzeRequest(messageInfo)
        headers  = list(analyzed.getHeaders())
        first_line = headers[0] if headers else ""
        parts = first_line.split(" ")
        method = parts[0] if len(parts) > 0 else "?"
        path   = parts[1] if len(parts) > 1 else "?"
        body   = request[analyzed.getBodyOffset():]
        body_b64 = base64.b64encode(bytes(bytearray(body))).decode("utf-8")
        host = service.getHost()
        sig = u"%s|%s|%s|%s" % (method, path, host, body_b64)
        return sig, method, path, len(request)

    def _add_history(self, messageInfo):
        try:
            sig, method, path, size = self._build_signature(messageInfo)

            for e in self.history:
                if e.get("sig") == sig:
                    return  
            service = messageInfo.getHttpService()
            ts = cairo_timestamp()
            entry = {
                "id":       self._next_hist_id[0],
                "method":   method,
                "path":     path,
                "size":     size,
                "time":     ts,
                "host":     service.getHost(),
                "port":     service.getPort(),
                "protocol": service.getProtocol(),
                "request":  messageInfo.getRequest(),
                "sig":      sig,
            }
            self._next_hist_id[0] += 1
            self.history.insert(0, entry)

            def _ui(e=entry):
                self.histModel.insertRow(0, [e["id"], e["method"], e["path"], e["size"], e["time"]])
            SwingUtilities.invokeLater(_ui)
            self._saveHistory()
        except Exception as ex:
            print("[History Error] " + str(ex))

    def _resendSelectedHistory(self):
        rows = self.histTable.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(self.main_panel, "No history rows selected.")
            return
        ids = []
        for r in rows:
            mr = self.histTable.convertRowIndexToModel(r)
            try:
                ids.append(int(str(self.histModel.getValueAt(mr, 0))))
            except:
                pass

        def _do():
            for hid in ids:
                entry = None
                for e in self.history:
                    if e["id"] == hid:
                        entry = e
                        break
                if not entry:
                    continue
                service = self.helpers.buildHttpService(
                    entry["host"], entry["port"], entry["protocol"] == "https")
                wrapper = HistoryMsgWrapper(entry["request"], service)
                self.send_all_roles_to_repeater(wrapper)
        self._enqueue_job(_do)

    def _deleteSelectedHistory(self):
        rows = sorted(self.histTable.getSelectedRows(), reverse=True)
        ids_to_del = set()
        for r in rows:
            mr = self.histTable.convertRowIndexToModel(r)
            try:
                ids_to_del.add(int(str(self.histModel.getValueAt(mr, 0))))
            except:
                pass
            self.histModel.removeRow(mr)
        self.history = [e for e in self.history if e["id"] not in ids_to_del]
        self._saveHistory()

    def _clearHistory(self):
        self.history = []
        self.histModel.setRowCount(0)
        self._next_hist_id[0] = 1
        self.current_hist_entry = None
        self._saveHistory()

    def _saveHistory(self):
        try:
            out = []
            for e in self.history:
                out.append({
                    "id":       e["id"],
                    "method":   e["method"],
                    "path":     e["path"],
                    "size":     e["size"],
                    "time":     e["time"],
                    "host":     e["host"],
                    "port":     e["port"],
                    "protocol": e["protocol"],
                    "request":  base64.b64encode(bytes(bytearray(e["request"]))).decode("utf-8"),
                    "sig":      e.get("sig", ""),
                })
            with open(HISTORY_FILE, "w") as f:
                json.dump({"history": out, "next_id": self._next_hist_id[0]}, f)
        except Exception as ex:
            print("[History Save Error] " + str(ex))

    def _loadHistory(self):
        try:
            if not os.path.exists(HISTORY_FILE):
                return
            with open(HISTORY_FILE, "r") as f:
                data = json.load(f)
            loaded = []
            for e in data.get("history", []):
                loaded.append({
                    "id":       e.get("id", 0),
                    "method":   e.get("method", "?"),
                    "path":     e.get("path", "?"),
                    "size":     e.get("size", 0),
                    "time":     e.get("time", ""),
                    "host":     e.get("host", ""),
                    "port":     e.get("port", 0),
                    "protocol": e.get("protocol", "https"),
                    "request":  bytearray(base64.b64decode(e["request"])),
                    "sig":      e.get("sig", ""),
                })
            self.history = loaded
            self._next_hist_id[0] = data.get("next_id", 1)

            def _ui():
                self.histModel.setRowCount(0)
                for e in self.history:
                    self.histModel.addRow([e["id"], e["method"], e["path"], e["size"], e["time"]])
            SwingUtilities.invokeLater(_ui)
            print("[+] Loaded %d history entries" % len(self.history))
        except Exception as ex:
            print("[History Load Error] " + str(ex))

    def _setStatus(self, msg, color=None):
        c = color if color else Color(150, 150, 150)
        self.lblStatus.setText("  " + msg)
        self.lblStatus.setForeground(c)

    def _clearAllBatches(self):
        self.results      = []
        self._batch_panels = []
        self._next_id[0]    = 1
        self._next_batch[0] = 1
        self._batch_tabs.removeAll()
        self._saveResults()
        self._setStatus("All batches cleared", Color(150, 150, 150))

    def _apply_font(self):
        try:
            self._current_font_size = int(str(self.spnFont.getValue()))
        except:
            return
        sz = self._current_font_size
        for rp in self.role_panels:
            rp.update_font(sz)
        for bp in self._batch_panels:
            bp.update_font(sz)
        self.lblStatus.setFont(Font("Monospaced", Font.PLAIN, sz))
        if hasattr(self, "histTable"):
            self.histTable.setFont(Font("Monospaced", Font.PLAIN, sz))
            self.histTable.setRowHeight(sz + 14)
            self.histTable.getTableHeader().setFont(Font("Monospaced", Font.BOLD, sz))
        self._saveSettings()

    def _serialize(self, lst):
        out = []
        for r in lst:
            out.append({
                "id":        r["id"],
                "local_id":  r.get("local_id"),
                "batch_id":  r.get("batch_id", 1),
                "label":     r["label"],
                "role":      r["role"],
                "status":    r["status"],
                "size":      r["size"],
                "host":      r["host"],
                "port":      r["port"],
                "protocol":  r["protocol"],
                "time":      r.get("time", ""),
                "method":    r.get("method", ""),
                "url":       r.get("url", ""),
                "params":    r.get("params", ""),
                "request":   base64.b64encode(bytes(bytearray(r["request"]))).decode("utf-8"),
                "response":  base64.b64encode(bytes(bytearray(r["response"]))).decode("utf-8") if r["response"] else "",
            })
        return out

    def _deserialize(self, lst):
        out = []
        for r in lst:
            out.append({
                "id":        r.get("id", 0),
                "local_id":  r.get("local_id"),
                "batch_id":  r.get("batch_id", 1),
                "label":     r["label"],
                "role":      r["role"],
                "status":    r["status"],
                "size":      r["size"],
                "host":      r["host"],
                "port":      r["port"],
                "protocol":  r["protocol"],
                "time":      r.get("time", ""),
                "method":    r.get("method", ""),
                "url":       r.get("url", ""),
                "params":    r.get("params", ""),
                "request":   bytearray(base64.b64decode(r["request"])),
                "response":  bytearray(base64.b64decode(r["response"])) if r["response"] else None,
            })
        return out

    def _saveResults(self):
        try:
            with open(SAVE_FILE, "w") as f:
                json.dump({
                    "results":    self._serialize(self.results),
                    "next_batch": self._next_batch[0],
                }, f)
        except Exception as e:
            print("[Save Error] " + str(e))

    def _loadResults(self):
        try:
            if not os.path.exists(SAVE_FILE): return
            with open(SAVE_FILE, "r") as f:
                data = json.load(f)
            self.results = self._deserialize(data.get("results", []))
            self._next_batch[0] = data.get("next_batch", 1)
            if self.results:
                self._next_id[0] = max(r["id"] for r in self.results) + 1
            SwingUtilities.invokeLater(self._rebuildBatchPanels)
            print("[+] Loaded %d results" % len(self.results))
        except Exception as e:
            print("[Load Error] " + str(e))

    def _rebuildBatchPanels(self):
        self._batch_tabs.removeAll()
        self._batch_panels = []

        batch_map   = {}
        batch_order = []
        for r in self.results:
            bid = r.get("batch_id", 1)
            if bid not in batch_map:
                batch_map[bid] = []
                batch_order.append(bid)
            batch_map[bid].append(r)

        for bid in batch_order:
            panel = BatchPanel(
                bid,
                self._colors_map,
                self._current_font_size,
                self._display_result,
                self._on_batch_delete_ids,
                self
            )
            for r in batch_map[bid]:
                panel.results.append(r)
            panel.refresh_table()
            self._batch_panels.append(panel)
            self._batch_tabs.addTab("Group %d" % bid, panel)

    def _saveSettings(self):
        try:
            s = {
                "font_size":       self._current_font_size,
                "rps":             self.fldRPS.getText(),
                "threads":         self.spnThreads.getValue(),
                "visible_columns": self._visible_columns,
            }
            with open(SETTINGS_FILE, "w") as f:
                json.dump(s, f, indent=2)
        except Exception as e:
            print("[Settings Save Error] " + str(e))

    def _loadSettings(self):
        try:
            if not os.path.exists(SETTINGS_FILE): return
            with open(SETTINGS_FILE, "r") as f:
                self._saved_settings = json.load(f)
            self._current_font_size = int(self._saved_settings.get("font_size", DEFAULT_FONT_SIZE))
            saved_cols = self._saved_settings.get("visible_columns")
            if isinstance(saved_cols, list) and saved_cols:
                self._visible_columns = [c for c in saved_cols if c in ALL_RESULT_COLUMNS] or list(DEFAULT_VISIBLE_COLUMNS)
        except Exception as e:
            print("[Settings Load Error] " + str(e))