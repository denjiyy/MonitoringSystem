#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import subprocess
import platform
import smtplib
import ftplib
import dns.resolver
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import os
from collections import deque
import logging
import ipaddress
import re
from typing import List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)

logging.getLogger().setLevel(logging.INFO)


class ConfigValidator:

    @staticmethod
    def validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port(port: int) -> bool:
        return 1 <= port <= 65535

    @staticmethod
    def validate_email(email: str) -> bool:
        if not email:
            return True
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_workstation_name(name: str) -> bool:
        return bool(name and len(name.strip()) > 0)


class MonitorConfig:

    def __init__(self, config_file='monitor_config.json'):
        self.config_file = config_file
        self.workstations = []
        self.check_interval = 60
        self.notification_email = ''
        self.smtp_server = ''
        self.smtp_port = 587
        self.smtp_user = ''
        self.smtp_password = ''
        self.retry_attempts = 2
        self.retry_delay = 1
        self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self._validate_and_load(config)
                logging.info("Configuration loaded successfully")
            else:
                self.create_default_config()
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in config file: {e}")
            self._backup_corrupt_config()
            self.create_default_config()
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            self.create_default_config()

    def _validate_and_load(self, config: dict):
        self.workstations = config.get('workstations', [])
        self.check_interval = max(10, config.get('check_interval', 60))
        self.notification_email = config.get('notification_email', '')
        self.smtp_server = config.get('smtp_server', '')
        self.smtp_port = config.get('smtp_port', 587)
        self.smtp_user = config.get('smtp_user', '')
        self.smtp_password = config.get('smtp_password', '')
        self.retry_attempts = config.get('retry_attempts', 2)
        self.retry_delay = config.get('retry_delay', 1)

        valid_workstations = []
        for ws in self.workstations:
            if ConfigValidator.validate_ip(ws.get('ip', '')):
                valid_workstations.append(ws)
            else:
                logging.warning(f"Invalid workstation IP: {ws.get('ip', 'unknown')}")
        self.workstations = valid_workstations

    def _backup_corrupt_config(self):
        try:
            backup_name = f"{self.config_file}.backup.{int(time.time())}"
            os.rename(self.config_file, backup_name)
            logging.info(f"Corrupted config backed up to {backup_name}")
        except Exception as e:
            logging.error(f"Could not backup corrupt config: {e}")

    def create_default_config(self):
        self.workstations = []
        self.check_interval = 60
        self.notification_email = ''
        self.smtp_server = ''
        self.smtp_port = 587
        self.smtp_user = ''
        self.smtp_password = ''
        self.retry_attempts = 2
        self.retry_delay = 1
        self.save_config()
        logging.info("Default configuration created")

    def save_config(self) -> bool:
        try:
            config = {
                'workstations': self.workstations,
                'check_interval': self.check_interval,
                'notification_email': self.notification_email,
                'smtp_server': self.smtp_server,
                'smtp_port': self.smtp_port,
                'smtp_user': self.smtp_user,
                'smtp_password': self.smtp_password,
                'retry_attempts': self.retry_attempts,
                'retry_delay': self.retry_delay
            }

            temp_file = f"{self.config_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(config, f, indent=4)

            os.replace(temp_file, self.config_file)
            logging.info("Configuration saved successfully")
            return True
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            return False

    def add_workstation(self, name: str, ip: str, services: dict, ports: dict = None) -> bool:
        if not ConfigValidator.validate_workstation_name(name):
            return False

        if not ConfigValidator.validate_ip(ip):
            return False

        for ws in self.workstations:
            if ws['name'] == name or ws['ip'] == ip:
                return False

        workstation = {
            'name': name,
            'ip': ip,
            'services': services,
            'ports': ports or {
                'http': 80,
                'smtp': 25,
                'pop3': 110,
                'ftp': 21
            }
        }

        self.workstations.append(workstation)
        return self.save_config()

    def update_workstation(self, old_name: str, name: str, ip: str,
                           services: dict, ports: dict) -> bool:
        if not ConfigValidator.validate_workstation_name(name):
            return False

        if not ConfigValidator.validate_ip(ip):
            return False

        for ws in self.workstations:
            if ws['name'] == old_name:
                for other_ws in self.workstations:
                    if other_ws['name'] != old_name:
                        if other_ws['name'] == name or other_ws['ip'] == ip:
                            return False

                ws['name'] = name
                ws['ip'] = ip
                ws['services'] = services
                ws['ports'] = ports
                return self.save_config()

        return False

    def remove_workstation(self, name: str) -> bool:
        self.workstations = [ws for ws in self.workstations if ws['name'] != name]
        return self.save_config()

    def get_workstation(self, name: str) -> Optional[dict]:
        for ws in self.workstations:
            if ws['name'] == name:
                return ws.copy()
        return None


class ServiceChecker:

    def __init__(self, retry_attempts=2, retry_delay=1):
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

    def _retry_check(self, check_func, *args, **kwargs):
        for attempt in range(self.retry_attempts):
            try:
                result = check_func(*args, **kwargs)
                if result:
                    return True
                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
            except Exception as e:
                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
                else:
                    raise
        return False

    def check_ping(self, host: str, timeout=2) -> bool:
        try:
            return self._retry_check(self._ping_once, host, timeout)
        except Exception as e:
            logging.debug(f"Ping check failed for {host}: {e}")
            return False

    def _ping_once(self, host: str, timeout: int) -> bool:
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            wait_flag = '-w' if platform.system().lower() == 'windows' else '-W'
            command = ['ping', param, '1', wait_flag, str(timeout), host]
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout + 1)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def check_dns(self, host: str, timeout=3) -> bool:
        try:
            return self._retry_check(self._dns_once, host, timeout)
        except Exception as e:
            logging.debug(f"DNS check failed for {host}: {e}")
            return False

    def _dns_once(self, host: str, timeout: int) -> bool:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [host]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.resolve('google.com', 'A')
        return True

    def check_http(self, host: str, port=80, timeout=3) -> bool:
        try:
            return self._retry_check(self._http_once, host, port, timeout)
        except Exception as e:
            logging.debug(f"HTTP check failed for {host}:{port}: {e}")
            return False

    def _http_once(self, host: str, port: int, timeout: int) -> bool:
        url = f"http://{host}:{port}"
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 500

    def check_smtp(self, host: str, port=25, timeout=3) -> bool:
        try:
            return self._retry_check(self._smtp_once, host, port, timeout)
        except Exception as e:
            logging.debug(f"SMTP check failed for {host}:{port}: {e}")
            return False

    def _smtp_once(self, host: str, port: int, timeout: int) -> bool:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.noop()
        return True

    def check_pop3(self, host: str, port=110, timeout=3) -> bool:
        try:
            return self._retry_check(self._pop3_once, host, port, timeout)
        except Exception as e:
            logging.debug(f"POP3 check failed for {host}:{port}: {e}")
            return False

    def _pop3_once(self, host: str, port: int, timeout: int) -> bool:
        import poplib
        pop = poplib.POP3(host, port, timeout=timeout)
        pop.quit()
        return True

    def check_ftp(self, host: str, port=21, timeout=3) -> bool:
        try:
            return self._retry_check(self._ftp_once, host, port, timeout)
        except Exception as e:
            logging.debug(f"FTP check failed for {host}:{port}: {e}")
            return False

    def _ftp_once(self, host: str, port: int, timeout: int) -> bool:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.quit()
        return True


class NotificationSystem:

    def __init__(self, config):
        self.config = config
        self.alert_history = deque(maxlen=100)
        self.last_alert_time = {}
        self.alert_cooldown = 300
        self._email_available = self._check_email_config()

    def _check_email_config(self) -> bool:
        return all([
            self.config.notification_email,
            self.config.smtp_server,
            self.config.smtp_user,
            self.config.smtp_password
        ])

    def send_email_notification(self, subject: str, body: str) -> bool:
        if not self._email_available:
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.smtp_user
            msg['To'] = self.config.notification_email
            msg['Subject'] = f"Network Monitor Alert: {subject}"

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port,
                              timeout=10) as server:
                server.starttls()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)

            logging.info(f"Email notification sent: {subject}")
            return True
        except Exception as e:
            logging.error(f"Failed to send email notification: {e}")
            self._email_available = False
            return False

    def send_desktop_notification(self, title: str, message: str):
        try:
            if platform.system() == 'Windows':
                try:
                    from win10toast import ToastNotifier
                    toaster = ToastNotifier()
                    toaster.show_toast(title, message, duration=10, threaded=True)
                except ImportError:
                    pass
            elif platform.system() == 'Darwin':
                os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
            else:
                os.system(f'notify-send "{title}" "{message}"')
        except Exception as e:
            logging.debug(f"Desktop notification failed: {e}")

    def notify(self, workstation_name: str, service: str, status: bool):
        if status:
            return

        alert_key = f"{workstation_name}_{service}"
        current_time = time.time()

        if alert_key in self.last_alert_time:
            if current_time - self.last_alert_time[alert_key] < self.alert_cooldown:
                return

        self.last_alert_time[alert_key] = current_time
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_msg = f"[{timestamp}] {workstation_name} - {service} is DOWN"
        self.alert_history.append(alert_msg)

        subject = f"{workstation_name} - {service} Down"
        body = f"Alert: {service} service on {workstation_name} is not responding.\n"
        body += f"Time: {timestamp}\n"
        body += f"Please investigate immediately."

        if self._email_available:
            self.send_email_notification(subject, body)

        self.send_desktop_notification("Network Monitor Alert", alert_msg)


class NetworkMonitor:

    def __init__(self, config):
        self.config = config
        self.checker = ServiceChecker(config.retry_attempts, config.retry_delay)
        self.notification_system = NotificationSystem(config)
        self.monitoring = False
        self.monitor_thread = None
        self.status_data = {}
        self.status_history = deque(maxlen=1000)
        self.lock = threading.RLock()
        self._stop_event = threading.Event()

    def check_workstation(self, workstation: dict) -> dict:
        results = {
            'name': workstation['name'],
            'ip': workstation['ip'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'services': {}
        }

        services = workstation.get('services', {})
        ports = workstation.get('ports', {})

        if services.get('ping', True):
            results['services']['ping'] = self.checker.check_ping(workstation['ip'])
            self.notification_system.notify(
                workstation['name'], 'Ping', results['services']['ping']
            )

        if results['services'].get('ping', False):
            if services.get('dns', False):
                results['services']['dns'] = self.checker.check_dns(workstation['ip'])
                self.notification_system.notify(
                    workstation['name'], 'DNS', results['services']['dns']
                )

            if services.get('http', False):
                port = ports.get('http', 80)
                results['services']['http'] = self.checker.check_http(
                    workstation['ip'], port
                )
                self.notification_system.notify(
                    workstation['name'], 'HTTP', results['services']['http']
                )

            if services.get('smtp', False):
                port = ports.get('smtp', 25)
                results['services']['smtp'] = self.checker.check_smtp(
                    workstation['ip'], port
                )
                self.notification_system.notify(
                    workstation['name'], 'SMTP', results['services']['smtp']
                )

            if services.get('pop3', False):
                port = ports.get('pop3', 110)
                results['services']['pop3'] = self.checker.check_pop3(
                    workstation['ip'], port
                )
                self.notification_system.notify(
                    workstation['name'], 'POP3', results['services']['pop3']
                )

            if services.get('ftp', False):
                port = ports.get('ftp', 21)
                results['services']['ftp'] = self.checker.check_ftp(
                    workstation['ip'], port
                )
                self.notification_system.notify(
                    workstation['name'], 'FTP', results['services']['ftp']
                )

        return results

    def monitor_loop(self):
        logging.info("Monitoring started")

        while not self._stop_event.is_set():
            if not self.monitoring:
                break

            check_start = time.time()

            threads = []
            results = []
            results_lock = threading.Lock()

            def check_and_store(ws):
                try:
                    result = self.check_workstation(ws)
                    with results_lock:
                        results.append(result)
                except Exception as e:
                    logging.error(f"Error checking {ws['name']}: {e}")

            for workstation in self.config.workstations:
                thread = threading.Thread(target=check_and_store, args=(workstation,))
                thread.daemon = True
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join(timeout=30)

            with self.lock:
                for result in results:
                    self.status_data[result['name']] = result
                    self.status_history.append(result)

            check_duration = time.time() - check_start
            wait_time = max(0, self.config.check_interval - check_duration)

            self._stop_event.wait(timeout=wait_time)

        logging.info("Monitoring stopped")

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self._stop_event.clear()
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self._stop_event.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def get_status(self) -> dict:
        with self.lock:
            return self.status_data.copy()

    def get_alerts(self) -> List[str]:
        return list(self.notification_system.alert_history)


class WorkstationDialog(tk.Toplevel):

    def __init__(self, parent, title="Add Workstation", workstation=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x550")
        self.resizable(False, False)

        self.result = None
        self.workstation = workstation or {}

        self.create_widgets()
        self.load_data()

        self.transient(parent)
        self.grab_set()

        self.wait_window()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill='both', expand=True)

        ttk.Label(main_frame, text="Workstation Name:").grid(
            row=0, column=0, sticky='w', pady=5
        )
        self.name_var = tk.StringVar()
        name_entry = ttk.Entry(main_frame, textvariable=self.name_var, width=40)
        name_entry.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(main_frame, text="IP Address:").grid(
            row=1, column=0, sticky='w', pady=5
        )
        self.ip_var = tk.StringVar()
        ip_entry = ttk.Entry(main_frame, textvariable=self.ip_var, width=40)
        ip_entry.grid(row=1, column=1, pady=5, padx=5)

        services_frame = ttk.LabelFrame(main_frame, text="Services to Monitor", padding="10")
        services_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=10)

        self.service_vars = {}
        services = ['ping', 'dns', 'http', 'smtp', 'pop3', 'ftp']

        for i, service in enumerate(services):
            var = tk.BooleanVar()
            self.service_vars[service] = var
            cb = ttk.Checkbutton(services_frame, text=service.upper(), variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky='w', padx=10, pady=5)

        ports_frame = ttk.LabelFrame(main_frame, text="Service Ports (optional)", padding="10")
        ports_frame.grid(row=3, column=0, columnspan=2, sticky='ew', pady=10)

        self.port_vars = {}
        port_services = ['http', 'smtp', 'pop3', 'ftp']
        defaults = {'http': 80, 'smtp': 25, 'pop3': 110, 'ftp': 21}

        for i, service in enumerate(port_services):
            ttk.Label(ports_frame, text=f"{service.upper()}:").grid(
                row=i // 2, column=(i % 2) * 2, sticky='w', padx=5, pady=3
            )
            var = tk.IntVar(value=defaults[service])
            self.port_vars[service] = var
            entry = ttk.Entry(ports_frame, textvariable=var, width=10)
            entry.grid(row=i // 2, column=(i % 2) * 2 + 1, padx=5, pady=3)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Save", command=self.save,
                   width=15).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel,
                   width=15).pack(side='left', padx=5)

    def load_data(self):
        if self.workstation:
            self.name_var.set(self.workstation.get('name', ''))
            self.ip_var.set(self.workstation.get('ip', ''))

            services = self.workstation.get('services', {})
            for service, var in self.service_vars.items():
                var.set(services.get(service, False))

            ports = self.workstation.get('ports', {})
            for service, var in self.port_vars.items():
                if service in ports:
                    var.set(ports[service])

    def validate(self) -> bool:
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Validation Error", "Workstation name is required")
            return False

        ip = self.ip_var.get().strip()
        if not ConfigValidator.validate_ip(ip):
            messagebox.showerror("Validation Error", "Invalid IP address format")
            return False

        for service, var in self.port_vars.items():
            try:
                port = var.get()
                if not ConfigValidator.validate_port(port):
                    messagebox.showerror(
                        "Validation Error",
                        f"Invalid port for {service.upper()}: must be 1-65535"
                    )
                    return False
            except:
                messagebox.showerror("Validation Error", f"Invalid port value for {service.upper()}")
                return False

        return True

    def save(self):
        if not self.validate():
            return

        self.result = {
            'name': self.name_var.get().strip(),
            'ip': self.ip_var.get().strip(),
            'services': {
                service: var.get()
                for service, var in self.service_vars.items()
            },
            'ports': {
                service: var.get()
                for service, var in self.port_vars.items()
            }
        }
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


class MonitorGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Office Network Monitoring System v2.0")
        self.root.geometry("1300x850")

        self.config = MonitorConfig()
        self.monitor = NetworkMonitor(self.config)

        self.create_menu()
        self.create_main_interface()

        self.update_display()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Settings", command=self.show_config_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        ws_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Workstations", menu=ws_menu)
        ws_menu.add_command(label="Add Workstation", command=self.add_workstation)
        ws_menu.add_command(label="Edit Workstation", command=self.edit_workstation)
        ws_menu.add_command(label="Remove Workstation", command=self.remove_workstation)

        monitor_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Monitor", menu=monitor_menu)
        monitor_menu.add_command(label="Start Monitoring", command=self.start_monitoring)
        monitor_menu.add_command(label="Stop Monitoring", command=self.stop_monitoring)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_main_interface(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        self.create_dashboard_tab()
        self.create_alerts_tab()
        self.create_logs_tab()

        self.status_var = tk.StringVar()
        self.status_var.set("Status: Stopped")
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def create_dashboard_tab(self):
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        control_frame = ttk.Frame(dashboard_frame)
        control_frame.pack(fill='x', padx=5, pady=5)

        self.start_btn = ttk.Button(control_frame, text="▶ Start Monitoring",
                                    command=self.start_monitoring)
        self.start_btn.pack(side='left', padx=5)

        self.stop_btn = ttk.Button(control_frame, text="⏸ Stop Monitoring",
                                   command=self.stop_monitoring, state='disabled')
        self.stop_btn.pack(side='left', padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side='left', fill='y',
                                                             padx=10, pady=5)

        ttk.Button(control_frame, text="➕ Add Workstation",
                   command=self.add_workstation).pack(side='left', padx=5)

        ttk.Button(control_frame, text="✏️ Edit",
                   command=self.edit_workstation).pack(side='left', padx=5)

        ttk.Button(control_frame, text="🗑️ Remove",
                   command=self.remove_workstation).pack(side='left', padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side='left', fill='y',
                                                             padx=10, pady=5)

        ttk.Button(control_frame, text="🔄 Refresh",
                   command=self.update_display).pack(side='left', padx=5)

        tree_frame = ttk.Frame(dashboard_frame)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")

        self.tree = ttk.Treeview(
            tree_frame,
            columns=('IP', 'Ping', 'DNS', 'HTTP', 'SMTP', 'POP3', 'FTP', 'Last Check'),
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        self.tree.heading('#0', text='Workstation')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Ping', text='Ping')
        self.tree.heading('DNS', text='DNS')
        self.tree.heading('HTTP', text='HTTP')
        self.tree.heading('SMTP', text='SMTP')
        self.tree.heading('POP3', text='POP3')
        self.tree.heading('FTP', text='FTP')
        self.tree.heading('Last Check', text='Last Check')

        self.tree.column('#0', width=180)
        self.tree.column('IP', width=130)
        for col in ('Ping', 'DNS', 'HTTP', 'SMTP', 'POP3', 'FTP'):
            self.tree.column(col, width=70, anchor='center')
        self.tree.column('Last Check', width=160)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure('up', foreground='green')
        self.tree.tag_configure('down', foreground='red')
        self.tree.tag_configure('na', foreground='gray')

    def create_alerts_tab(self):
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="Alerts")

        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=35, width=120)
        self.alerts_text.pack(fill='both', expand=True, padx=5, pady=5)

        ttk.Button(alerts_frame, text="Clear Alerts",
                   command=self.clear_alerts).pack(pady=5)

    def create_logs_tab(self):
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")

        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=35, width=120)
        self.logs_text.pack(fill='both', expand=True, padx=5, pady=5)

        button_frame = ttk.Frame(logs_frame)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="Refresh Logs",
                   command=self.load_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Clear Display",
                   command=lambda: self.logs_text.delete(1.0, tk.END)).pack(side='left', padx=5)

        self.load_logs()

    def add_workstation(self):
        dialog = WorkstationDialog(self.root, "Add Workstation")

        if dialog.result:
            if self.config.add_workstation(
                    dialog.result['name'],
                    dialog.result['ip'],
                    dialog.result['services'],
                    dialog.result['ports']
            ):
                messagebox.showinfo("Success", "Workstation added successfully")
                self.update_display()
            else:
                messagebox.showerror("Error",
                                     "Failed to add workstation. Name or IP may already exist.")

    def edit_workstation(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a workstation to edit")
            return

        item = self.tree.item(selection[0])
        ws_name = item['text']

        workstation = self.config.get_workstation(ws_name)
        if not workstation:
            messagebox.showerror("Error", "Workstation not found")
            return

        dialog = WorkstationDialog(self.root, "Edit Workstation", workstation)

        if dialog.result:
            if self.config.update_workstation(
                    ws_name,
                    dialog.result['name'],
                    dialog.result['ip'],
                    dialog.result['services'],
                    dialog.result['ports']
            ):
                messagebox.showinfo("Success", "Workstation updated successfully")
                self.update_display()
            else:
                messagebox.showerror("Error", "Failed to update workstation")

    def remove_workstation(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a workstation to remove")
            return

        item = self.tree.item(selection[0])
        ws_name = item['text']

        if messagebox.askyesno("Confirm Removal",
                               f"Are you sure you want to remove '{ws_name}'?"):
            if self.config.remove_workstation(ws_name):
                messagebox.showinfo("Success", "Workstation removed successfully")
                self.update_display()
            else:
                messagebox.showerror("Error", "Failed to remove workstation")

    def start_monitoring(self):
        if not self.config.workstations:
            messagebox.showwarning("No Workstations",
                                   "Please add workstations before starting monitoring")
            return

        self.monitor.start_monitoring()
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("Status: ✓ Monitoring Active")
        logging.info("Monitoring started via GUI")

    def stop_monitoring(self):
        self.monitor.stop_monitoring()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Status: ⏸ Stopped")
        logging.info("Monitoring stopped via GUI")

    def update_display(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        status = self.monitor.get_status()

        if not status:
            for ws in self.config.workstations:
                values = (ws['ip'], '-', '-', '-', '-', '-', '-', 'Not checked')
                self.tree.insert('', 'end', text=ws['name'], values=values, tags=('na',))
        else:
            for ws_name, data in status.items():
                services = data.get('services', {})

                def format_status(service_name):
                    if service_name in services:
                        return '✓' if services[service_name] else '✗'
                    return '-'

                tag = 'na'
                if 'ping' in services:
                    tag = 'up' if services['ping'] else 'down'

                values = (
                    data['ip'],
                    format_status('ping'),
                    format_status('dns'),
                    format_status('http'),
                    format_status('smtp'),
                    format_status('pop3'),
                    format_status('ftp'),
                    data['timestamp']
                )

                self.tree.insert('', 'end', text=ws_name, values=values, tags=(tag,))

        self.update_alerts()

        ws_count = len(self.config.workstations)
        current_status = self.status_var.get()
        if "Stopped" in current_status:
            self.status_var.set(f"Status: ⏸ Stopped | {ws_count} workstation(s) configured")
        elif "Active" in current_status:
            self.status_var.set(f"Status: ✓ Monitoring Active | {ws_count} workstation(s)")

        self.root.after(2000, self.update_display)

    def update_alerts(self):
        self.alerts_text.delete(1.0, tk.END)
        alerts = self.monitor.get_alerts()
        if alerts:
            for alert in reversed(alerts):
                self.alerts_text.insert(tk.END, alert + '\n')
        else:
            self.alerts_text.insert(tk.END, "No alerts at this time.\n")

    def clear_alerts(self):
        self.monitor.notification_system.alert_history.clear()
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(tk.END, "Alerts cleared.\n")

    def load_logs(self):
        self.logs_text.delete(1.0, tk.END)
        try:
            if os.path.exists('network_monitor.log'):
                with open('network_monitor.log', 'r') as f:
                    logs = f.readlines()
                    for line in logs[-200:]:
                        self.logs_text.insert(tk.END, line)
                self.logs_text.see(tk.END)
            else:
                self.logs_text.insert(tk.END, "No log file found.\n")
        except Exception as e:
            self.logs_text.insert(tk.END, f"Error loading logs: {e}\n")

    def show_config_dialog(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Settings")
        config_window.geometry("650x500")
        config_window.resizable(False, False)

        notebook = ttk.Notebook(config_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        general_frame = ttk.Frame(notebook, padding="15")
        notebook.add(general_frame, text="General")

        ttk.Label(general_frame, text="Check Interval (seconds):").grid(
            row=0, column=0, padx=5, pady=10, sticky='w'
        )
        interval_var = tk.IntVar(value=self.config.check_interval)
        ttk.Spinbox(general_frame, from_=10, to=3600, textvariable=interval_var,
                    width=15).grid(row=0, column=1, padx=5, pady=10)

        ttk.Label(general_frame, text="Retry Attempts:").grid(
            row=1, column=0, padx=5, pady=10, sticky='w'
        )
        retry_var = tk.IntVar(value=self.config.retry_attempts)
        ttk.Spinbox(general_frame, from_=1, to=5, textvariable=retry_var,
                    width=15).grid(row=1, column=1, padx=5, pady=10)

        ttk.Label(general_frame, text="Retry Delay (seconds):").grid(
            row=2, column=0, padx=5, pady=10, sticky='w'
        )
        delay_var = tk.IntVar(value=self.config.retry_delay)
        ttk.Spinbox(general_frame, from_=1, to=10, textvariable=delay_var,
                    width=15).grid(row=2, column=1, padx=5, pady=10)

        email_frame = ttk.Frame(notebook, padding="15")
        notebook.add(email_frame, text="Email Notifications")

        ttk.Label(email_frame, text="Notification Email:").grid(
            row=0, column=0, padx=5, pady=8, sticky='w'
        )
        email_var = tk.StringVar(value=self.config.notification_email)
        ttk.Entry(email_frame, textvariable=email_var, width=45).grid(
            row=0, column=1, padx=5, pady=8
        )

        ttk.Label(email_frame, text="SMTP Server:").grid(
            row=1, column=0, padx=5, pady=8, sticky='w'
        )
        smtp_server_var = tk.StringVar(value=self.config.smtp_server)
        ttk.Entry(email_frame, textvariable=smtp_server_var, width=45).grid(
            row=1, column=1, padx=5, pady=8
        )

        ttk.Label(email_frame, text="SMTP Port:").grid(
            row=2, column=0, padx=5, pady=8, sticky='w'
        )
        smtp_port_var = tk.IntVar(value=self.config.smtp_port)
        ttk.Entry(email_frame, textvariable=smtp_port_var, width=45).grid(
            row=2, column=1, padx=5, pady=8
        )

        ttk.Label(email_frame, text="SMTP Username:").grid(
            row=3, column=0, padx=5, pady=8, sticky='w'
        )
        smtp_user_var = tk.StringVar(value=self.config.smtp_user)
        ttk.Entry(email_frame, textvariable=smtp_user_var, width=45).grid(
            row=3, column=1, padx=5, pady=8
        )

        ttk.Label(email_frame, text="SMTP Password:").grid(
            row=4, column=0, padx=5, pady=8, sticky='w'
        )
        smtp_pass_var = tk.StringVar(value=self.config.smtp_password)
        ttk.Entry(email_frame, textvariable=smtp_pass_var, show='*', width=45).grid(
            row=4, column=1, padx=5, pady=8
        )

        info_text = "Leave email settings empty to disable email notifications"
        ttk.Label(email_frame, text=info_text, font=('Arial', 9, 'italic'),
                  foreground='gray').grid(row=5, column=0, columnspan=2, pady=15)

        def save_config():
            email = email_var.get().strip()
            if email and not ConfigValidator.validate_email(email):
                messagebox.showerror("Validation Error", "Invalid email address format")
                return

            self.config.check_interval = max(10, interval_var.get())
            self.config.retry_attempts = retry_var.get()
            self.config.retry_delay = delay_var.get()
            self.config.notification_email = email
            self.config.smtp_server = smtp_server_var.get().strip()
            self.config.smtp_port = smtp_port_var.get()
            self.config.smtp_user = smtp_user_var.get().strip()
            self.config.smtp_password = smtp_pass_var.get()

            if self.config.save_config():
                self.monitor.checker = ServiceChecker(
                    self.config.retry_attempts,
                    self.config.retry_delay
                )
                self.monitor.notification_system = NotificationSystem(self.config)

                messagebox.showinfo("Success", "Settings saved successfully")
                config_window.destroy()
            else:
                messagebox.showerror("Error", "Failed to save settings")

        button_frame = ttk.Frame(config_window)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Save", command=save_config,
                   width=15).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=config_window.destroy,
                   width=15).pack(side='left', padx=5)

    def show_about(self):
        messagebox.showinfo("About",
                            "Office Network Monitoring System\n\n"
                            "Version 2.0 - Production Release\n\n"
                            "A comprehensive, enterprise-grade network\n"
                            "monitoring solution for office networks.\n\n"
                            "Features:\n"
                            "• Real-time service monitoring\n"
                            "• Multi-threaded concurrent checks\n"
                            "• GUI-based workstation management\n"
                            "• Email & desktop notifications\n"
                            "• Comprehensive logging\n\n"
                            "Monitors: Ping, DNS, HTTP, SMTP, POP3, FTP")

    def on_closing(self):
        if self.monitor.monitoring:
            if messagebox.askyesno("Quit",
                                   "Monitoring is active. Stop monitoring and quit?"):
                self.monitor.stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    try:
        import dns.resolver
        import requests
    except ImportError as e:
        print(f"Missing required dependency: {e}")
        print("\nPlease install required packages:")
        print("pip install dnspython requests")
        return

    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
