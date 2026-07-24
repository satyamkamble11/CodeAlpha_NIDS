import sys
import queue
import os
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QLineEdit, QSplitter, QTextEdit, QFileDialog, QMessageBox,
    QCheckBox, QFrame, QGroupBox, QDialog, QDialogButtonBox
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont, QColor

import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from ids_engine import IDSEngine
from db import fetch_alerts, clear_db, export_alerts_to_csv, export_alerts_to_json
from rules import RuleEngine

# Modern Dark NIDS Cyber Dashboard Stylesheet
DARK_NIDS_THEME = """
QMainWindow {
    background-color: #0F172A;
}
QWidget {
    background-color: #1E293B;
    color: #F8FAFC;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
QFrame, QGroupBox {
    border: 1px solid #334155;
    border-radius: 8px;
    margin-top: 6px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px 0 5px;
    color: #38BDF8;
    font-weight: bold;
}
QPushButton {
    background-color: #334155;
    color: #F8FAFC;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #475569;
}
QPushButton#startBtn {
    background-color: #15803D;
    color: #FFFFFF;
    border: 1px solid #166534;
}
QPushButton#startBtn:hover {
    background-color: #166534;
}
QPushButton#stopBtn {
    background-color: #B91C1C;
    color: #FFFFFF;
    border: 1px solid #991B1B;
}
QPushButton#stopBtn:hover {
    background-color: #991B1B;
}
QPushButton#blockBtn {
    background-color: #DC2626;
    color: #FFFFFF;
    font-weight: bold;
}
QComboBox, QLineEdit {
    background-color: #0F172A;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 5px 8px;
}
QTableWidget {
    background-color: #0F172A;
    gridline-color: #334155;
    border: 1px solid #334155;
    border-radius: 6px;
    selection-background-color: #334155;
}
QHeaderView::section {
    background-color: #1E293B;
    color: #38BDF8;
    padding: 6px;
    border: 1px solid #334155;
    font-weight: bold;
}
QTextEdit {
    background-color: #020617;
    color: #38BDF8;
    font-family: 'Consolas', 'Courier New', monospace;
    border: 1px solid #334155;
    border-radius: 6px;
}
"""

class TopAttackingIPsCanvas(FigureCanvas):
    def __init__(self, parent=None, width=4, height=2.5, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        fig.patch.set_facecolor('#1E293B')
        self.axes = fig.add_subplot(111)
        self.axes.set_facecolor('#1E293B')
        super().__init__(fig)
        self.setParent(parent)

    def update_chart(self, alerts):
        self.axes.clear()
        if not alerts:
            self.axes.text(0.5, 0.5, 'No Threat Data', color='#38BDF8',
                           ha='center', va='center', fontsize=11, fontweight='bold')
            self.axes.axis('off')
        else:
            df = pd.DataFrame(alerts)
            top_ips = df['src_ip'].value_counts().head(5)
            
            ips = list(top_ips.index)
            counts = list(top_ips.values)
            
            bars = self.axes.barh(ips, counts, color='#EF4444')
            self.axes.set_title("Top 5 Attacking Source IPs", color="#F8FAFC", fontsize=11, fontweight='bold')
            self.axes.tick_params(colors='#F8FAFC')
            self.axes.invert_yaxis()  # top attacker at top
            
            for spine in self.axes.spines.values():
                spine.set_color('#334155')

        self.figure.tight_layout()
        self.draw()


class AttackTypeDonutCanvas(FigureCanvas):
    def __init__(self, parent=None, width=4, height=2.5, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        fig.patch.set_facecolor('#1E293B')
        self.axes = fig.add_subplot(111)
        self.axes.set_facecolor('#1E293B')
        super().__init__(fig)
        self.setParent(parent)

    def update_chart(self, alerts):
        self.axes.clear()
        if not alerts:
            self.axes.text(0.5, 0.5, 'No Attack Data', color='#38BDF8',
                           ha='center', va='center', fontsize=11, fontweight='bold')
            self.axes.axis('off')
        else:
            df = pd.DataFrame(alerts)
            types = df['attack_type'].value_counts()
            
            labels = list(types.index)
            sizes = list(types.values)
            colors = ['#EF4444', '#F59E0B', '#3B82F6', '#8B5CF6', '#10B981']

            wedges, texts, autotexts = self.axes.pie(
                sizes, labels=labels, autopct='%1.0f%%',
                colors=colors[:len(labels)], startangle=140,
                pctdistance=0.75, textprops=dict(color="#F8FAFC", fontsize=9)
            )
            # Create Donut hole
            centre_circle = matplotlib.patches.Circle((0,0), 0.50, fc='#1E293B')
            self.axes.add_artist(centre_circle)
            self.axes.set_title("Attack Type Distribution", color="#F8FAFC", fontsize=11, fontweight='bold')
            self.axes.axis('equal')

        self.figure.tight_layout()
        self.draw()


class NIDSGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeAlpha - Network Intrusion Detection System (NIDS)")
        self.resize(1300, 850)
        self.setStyleSheet(DARK_NIDS_THEME)

        self.alert_queue = queue.Queue()
        self.packet_queue = queue.Queue()
        self.ids_engine = IDSEngine(alert_queue=self.alert_queue, packet_queue=self.packet_queue)

        self.all_alerts = []
        self.filtered_alerts = []
        self.selected_alert = None
        self.packets_analyzed = 0

        self.init_ui()

        # Alert Queue Polling Timer (200ms)
        self.timer = QTimer(self)
        self.timer.setInterval(200)
        self.timer.timeout.connect(self.process_queues)
        self.timer.start()

        # Chart Refresh Timer (every 4 seconds)
        self.chart_timer = QTimer(self)
        self.chart_timer.setInterval(4000)
        self.chart_timer.timeout.connect(self.refresh_charts)
        self.chart_timer.start()

        # Load existing alerts from SQLite on boot
        self.load_alerts_from_db()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # ---------------- Top Control Bar ----------------
        top_box = QGroupBox("NIDS Engine Controls")
        top_layout = QHBoxLayout(top_box)

        self.status_label = QLabel("SYSTEM STATUS: STOPPED 🔴")
        self.status_label.setStyleSheet("color: #EF4444; font-weight: bold; font-size: 14px;")

        self.start_btn = QPushButton("🛡️ Start Monitoring")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_monitoring)

        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_monitoring)

        self.clear_btn = QPushButton("🗑 Clear Alerts")
        self.clear_btn.clicked.connect(self.clear_alerts_action)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(180)
        from sniffer import PacketSniffer
        self.iface_combo.addItems(PacketSniffer.get_available_interfaces())

        top_layout.addWidget(self.status_label)
        top_layout.addWidget(self.start_btn)
        top_layout.addWidget(self.stop_btn)
        top_layout.addWidget(self.clear_btn)
        top_layout.addWidget(QLabel("Interface:"))
        top_layout.addWidget(self.iface_combo)

        main_layout.addWidget(top_box)

        # ---------------- Main Splitter (Left: Alerts Table & Details, Right: Visual Analytics) ----------------
        splitter = QSplitter(Qt.Horizontal)

        # --- Left Panel: Real-Time Alert Feed & Filters ---
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Filter Controls Bar
        filter_box = QHBoxLayout()
        filter_box.addWidget(QLabel("🔍 IP Search:"))
        self.search_ip_input = QLineEdit()
        self.search_ip_input.setPlaceholderText("Search IP...")
        self.search_ip_input.textChanged.connect(self.apply_filters)
        filter_box.addWidget(self.search_ip_input)

        filter_box.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["ALL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_combo.currentTextChanged.connect(self.apply_filters)
        filter_box.addWidget(self.severity_combo)

        filter_box.addWidget(QLabel("Attack Type:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["ALL", "PORT_SCAN", "PING_FLOOD", "SQL_INJECTION", "BRUTE_FORCE_SSH", "ARP_SPOOFING"])
        self.attack_type_combo.currentTextChanged.connect(self.apply_filters)
        filter_box.addWidget(self.attack_type_combo)

        left_layout.addLayout(filter_box)

        # Alerts Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["ID", "Timestamp", "Severity", "Attack Type", "Source IP", "Destination IP", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self.on_alert_selected)
        left_layout.addWidget(self.table)

        # Alert Inspection & IP Action Bar
        action_box = QHBoxLayout()
        self.block_ip_btn = QPushButton("🚫 Block IP (Add to Blocklist)")
        self.block_ip_btn.setObjectName("blockBtn")
        self.block_ip_btn.clicked.connect(self.block_selected_ip)
        
        self.export_csv_btn = QPushButton("💾 Export CSV")
        self.export_csv_btn.clicked.connect(self.export_csv_action)
        
        self.export_json_btn = QPushButton("💾 Export JSON")
        self.export_json_btn.clicked.connect(self.export_json_action)

        action_box.addWidget(self.block_ip_btn)
        action_box.addWidget(self.export_csv_btn)
        action_box.addWidget(self.export_json_btn)
        left_layout.addLayout(action_box)

        # Selected Alert Payload Inspector
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(150)
        self.detail_text.setPlaceholderText("Select an alert row above to inspect matched rule details and hex payload...")
        left_layout.addWidget(self.detail_text)

        splitter.addWidget(left_container)

        # --- Right Panel: Threat Charts & KPI Cards ---
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # KPI Counter Cards Box
        kpi_box = QGroupBox("Security Metrics Summary")
        kpi_layout = QHBoxLayout(kpi_box)

        self.kpi_total = QLabel("Total Alerts: 0")
        self.kpi_high = QLabel("HIGH: 0")
        self.kpi_med = QLabel("MED: 0")
        self.kpi_low = QLabel("LOW: 0")
        
        self.kpi_high.setStyleSheet("background: #451E2B; color: #EF4444; padding: 6px; font-weight: bold; border-radius: 4px;")
        self.kpi_med.setStyleSheet("background: #452A15; color: #F59E0B; padding: 6px; font-weight: bold; border-radius: 4px;")
        self.kpi_low.setStyleSheet("background: #163045; color: #3B82F6; padding: 6px; font-weight: bold; border-radius: 4px;")
        self.kpi_total.setStyleSheet("background: #334155; color: #F8FAFC; padding: 6px; font-weight: bold; border-radius: 4px;")

        kpi_layout.addWidget(self.kpi_total)
        kpi_layout.addWidget(self.kpi_high)
        kpi_layout.addWidget(self.kpi_med)
        kpi_layout.addWidget(self.kpi_low)
        right_layout.addWidget(kpi_box)

        # Matplotlib Charts
        self.top_ips_chart = TopAttackingIPsCanvas(self, width=4, height=2.5)
        self.donut_chart = AttackTypeDonutCanvas(self, width=4, height=2.5)

        right_layout.addWidget(self.top_ips_chart)
        right_layout.addWidget(self.donut_chart)

        splitter.addWidget(right_container)
        splitter.setSizes([780, 500])

        main_layout.addWidget(splitter)

        # ---------------- Bottom Status Footer ----------------
        self.footer_label = QLabel("Packets Analyzed: 0 | Encrypted Traffic Note: Layer 7 payload inspection limited to unencrypted protocols.")
        self.footer_label.setStyleSheet("color: #64748B; font-size: 12px;")
        main_layout.addWidget(self.footer_label)

    def start_monitoring(self):
        iface = self.iface_combo.currentText()
        success, msg = self.ids_engine.start(interface=iface)
        if success:
            self.status_label.setText("SYSTEM STATUS: MONITORING ACTIVE 🟢")
            self.status_label.setStyleSheet("color: #10B981; font-weight: bold; font-size: 14px;")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.iface_combo.setEnabled(False)
        else:
            QMessageBox.warning(self, "Start Error", msg)

    def stop_monitoring(self):
        self.ids_engine.stop()
        self.status_label.setText("SYSTEM STATUS: STOPPED 🔴")
        self.status_label.setStyleSheet("color: #EF4444; font-weight: bold; font-size: 14px;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)

    def load_alerts_from_db(self):
        self.all_alerts = fetch_alerts(self.ids_engine.db_path)
        self.apply_filters()
        self.update_kpi_summary()
        self.refresh_charts()

    def process_queues(self):
        # Read incoming packets for counter
        while not self.packet_queue.empty():
            self.packet_queue.get()
            self.packets_analyzed += 1

        new_alert = False
        while not self.alert_queue.empty():
            alert = self.alert_queue.get()
            if alert.get("id") == -1:
                QMessageBox.critical(self, "Engine Error", alert.get("description"))
                self.stop_monitoring()
                break

            self.all_alerts.insert(0, alert)
            new_alert = True

        if new_alert:
            self.apply_filters()
            self.update_kpi_summary()

        self.footer_label.setText(f"Packets Analyzed: {self.packets_analyzed} | Encrypted Traffic Note: Layer 7 payload inspection limited to unencrypted protocols.")

    def apply_filters(self):
        ip_search = self.search_ip_input.text().strip().lower()
        selected_severity = self.severity_combo.currentText()
        selected_attack = self.attack_type_combo.currentText()

        self.filtered_alerts = []
        for alert in self.all_alerts:
            # IP match
            ip_match = True
            if ip_search:
                ip_match = (ip_search in alert['src_ip'].lower()) or (ip_search in alert['dst_ip'].lower())

            # Severity match
            sev_match = True
            if selected_severity != "ALL":
                sev_match = (alert['severity'] == selected_severity)

            # Attack type match
            atk_match = True
            if selected_attack != "ALL":
                atk_match = (alert['attack_type'] == selected_attack)

            if ip_match and sev_match and atk_match:
                self.filtered_alerts.append(alert)

        self.table.setRowCount(len(self.filtered_alerts))
        for row_idx, alert in enumerate(self.filtered_alerts):
            self.table.setItem(row_idx, 0, QTableWidgetItem(str(alert['id'])))
            self.table.setItem(row_idx, 1, QTableWidgetItem(alert['timestamp']))
            self.table.setItem(row_idx, 2, QTableWidgetItem(alert['severity']))
            self.table.setItem(row_idx, 3, QTableWidgetItem(alert['attack_type']))
            self.table.setItem(row_idx, 4, QTableWidgetItem(alert['src_ip']))
            self.table.setItem(row_idx, 5, QTableWidgetItem(alert['dst_ip']))
            self.table.setItem(row_idx, 6, QTableWidgetItem(alert['description']))

            # Row Color Coding by Severity
            sev = alert['severity']
            bg_color = QColor('#1E293B')
            text_color = QColor('#F8FAFC')

            if sev == "HIGH":
                bg_color = QColor('#451E2B')
                text_color = QColor('#EF4444')
            elif sev == "MEDIUM":
                bg_color = QColor('#452A15')
                text_color = QColor('#F59E0B')
            elif sev == "LOW":
                bg_color = QColor('#163045')
                text_color = QColor('#3B82F6')

            for col in range(7):
                item = self.table.item(row_idx, col)
                if item:
                    item.setBackground(bg_color)
                    item.setForeground(text_color)
                    if sev == "HIGH":
                        item.setFont(QFont("Segoe UI", 10, QFont.Bold))

    def on_alert_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < len(self.filtered_alerts):
            alert = self.filtered_alerts[row]
            self.selected_alert = alert

            details = f"""
==================================================
NIDS THREAT ALERT INSPECTOR - ALERT #{alert['id']}
==================================================
Timestamp    : {alert['timestamp']}
Severity     : {alert['severity']}
Attack Type  : {alert['attack_type']}
Rule Trigger : {alert['rule_name']}
Source IP    : {alert['src_ip']}
Target IP    : {alert['dst_ip']}
Description  : {alert['description']}
==================================================
RAW PAYLOAD / EVIDENCE DUMP:
{alert.get('raw_payload', 'No payload capture available.')}
"""
            self.detail_text.setText(details)

    def block_selected_ip(self):
        if not self.selected_alert:
            QMessageBox.information(self, "Block IP", "Please select an alert from the table first.")
            return

        target_ip = self.selected_alert['src_ip']
        try:
            with open("blocklist.txt", "a") as f:
                f.write(f"{target_ip} # Blocked via NIDS GUI on {self.selected_alert['timestamp']}\n")
            QMessageBox.warning(self, "IP Blocked", f"🚫 IP Address {target_ip} has been added to blocklist.txt!")
        except Exception as e:
            QMessageBox.critical(self, "Block Failed", f"Could not write to blocklist: {e}")

    def update_kpi_summary(self):
        total = len(self.all_alerts)
        high = sum(1 for a in self.all_alerts if a['severity'] == "HIGH")
        med = sum(1 for a in self.all_alerts if a['severity'] == "MEDIUM")
        low = sum(1 for a in self.all_alerts if a['severity'] == "LOW")

        self.kpi_total.setText(f"Total Alerts: {total}")
        self.kpi_high.setText(f"HIGH: {high}")
        self.kpi_med.setText(f"MED: {med}")
        self.kpi_low.setText(f"LOW: {low}")

    def refresh_charts(self):
        self.top_ips_chart.update_chart(self.all_alerts)
        self.donut_chart.update_chart(self.all_alerts)

    def clear_alerts_action(self):
        reply = QMessageBox.question(self, "Clear Alerts", "Are you sure you want to clear all alerts from database?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            clear_db(self.ids_engine.db_path)
            self.all_alerts.clear()
            self.filtered_alerts.clear()
            self.table.setRowCount(0)
            self.detail_text.clear()
            self.update_kpi_summary()
            self.refresh_charts()

    def export_csv_action(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Export NIDS Alerts CSV", "nids_alerts.csv", "CSV Files (*.csv)")
        if filepath:
            success, msg = export_alerts_to_csv(filepath, db_path=self.ids_engine.db_path)
            if success:
                QMessageBox.information(self, "Export Success", msg)
            else:
                QMessageBox.critical(self, "Export Error", msg)

    def export_json_action(self):
        filepath, _ = QFileDialog.getSaveFileName(self, "Export NIDS Alerts JSON", "nids_alerts.json", "JSON Files (*.json)")
        if filepath:
            success, msg = export_alerts_to_json(filepath, db_path=self.ids_engine.db_path)
            if success:
                QMessageBox.information(self, "Export Success", msg)
            else:
                QMessageBox.critical(self, "Export Error", msg)

def main():
    app = QApplication(sys.argv)
    window = NIDSGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
