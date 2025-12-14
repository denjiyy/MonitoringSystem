# 🖥️ Office Network Monitoring System

A comprehensive, enterprise-grade network monitoring solution designed for small to medium office environments. Monitor the health and availability of workstations and network services in real-time with an intuitive graphical interface.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## ✨ Features

- **🎯 Real-time Monitoring** - Continuous health checks with configurable intervals
- **🔄 Concurrent Checks** - Multi-threaded architecture monitors all workstations simultaneously
- **📊 Service Monitoring** - Track Ping, DNS, HTTP, SMTP, POP3, and FTP services
- **🖱️ GUI Management** - Add, edit, and remove workstations directly from the interface
- **🔔 Smart Notifications** - Email and desktop alerts with cooldown periods to prevent spam
- **📝 Comprehensive Logging** - Detailed audit trail of all monitoring activities
- **⚙️ Flexible Configuration** - Customize check intervals, retry attempts, and service ports
- **🎨 Color-Coded Status** - Instant visual feedback with green (up), red (down), and gray (unchecked) indicators
- **🔒 Input Validation** - Robust error handling prevents configuration mistakes

## 📋 Requirements

- Python 3.7 or higher
- Network access to monitored devices
- Minimal system resources (< 50MB RAM)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/network-monitor.git
cd network-monitor
```

### 2. Create a Virtual Environment (Recommended)

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python main.py
```

## 📖 Usage Guide

### Adding Your First Workstation

1. **Launch the application** by running `python main.py`
2. **Click "➕ Add Workstation"** in the dashboard
3. **Fill in the details:**
   - **Name:** A friendly identifier (e.g., "Server-01", "Router")
   - **IP Address:** The device's IP address (e.g., "192.168.1.100")
   - **Services:** Check which services to monitor
   - **Ports:** Customize if using non-standard ports
4. **Click "Save"**

### Starting Monitoring

1. After adding workstations, click **"▶ Start Monitoring"**
2. The system will begin checking all configured workstations
3. Status updates appear every 2 seconds in the dashboard
4. Check marks (✓) indicate services are up, X marks (✗) indicate down

### Managing Workstations

- **Edit:** Select a workstation in the list and click **"✏️ Edit"**
- **Remove:** Select a workstation and click **"🗑️ Remove"** (with confirmation)
- **Refresh:** Click **"🔄 Refresh"** to manually update the display

### Viewing Alerts

Switch to the **"Alerts"** tab to see a chronological list of all detected issues with timestamps.

### Checking Logs

The **"Logs"** tab displays the last 200 lines from `network_monitor.log` for detailed troubleshooting.

## ⚙️ Configuration

### System Settings

Access via **File → Settings** or click the **Configure** button:

**General Settings:**
- **Check Interval:** How often to check workstations (10-3600 seconds)
- **Retry Attempts:** Number of retries before marking a service as down (1-5)
- **Retry Delay:** Seconds between retry attempts (1-10)

**Email Notifications:**
- **Notification Email:** Where to send alerts
- **SMTP Server:** Your mail server (e.g., smtp.gmail.com)
- **SMTP Port:** Usually 587 for TLS
- **SMTP Username:** Your email account
- **SMTP Password:** Your email password

*Note: Leave email settings empty to disable email notifications*

### Configuration File

Settings are stored in `monitor_config.json` in the same directory as the script. While you can edit this manually, it's recommended to use the GUI to prevent errors.

## 🧪 Testing with Public Servers

Here are some reliable public IPs you can use to test the monitoring system:

| Name | IP Address | Services | Description |
|------|------------|----------|-------------|
| Cloudflare DNS | 1.1.1.1 | Ping, DNS, HTTP | Fast, reliable DNS service |
| Google DNS | 8.8.8.8 | Ping, DNS | Google's public DNS |
| Quad9 DNS | 9.9.9.9 | Ping, DNS | Privacy-focused DNS |
| Google.com | 142.250.185.78 | Ping, HTTP | Google's domain |

### Quick Test Setup

1. Add **Cloudflare DNS** (1.1.1.1) with Ping, DNS, and HTTP enabled
2. Start monitoring
3. You should see green checkmarks (✓) for all three services within seconds

### Testing SMTP, POP3, and FTP

These services are rarely available on public IPs due to security concerns. To test them:

**Option 1: Use Your Router**
- Your local router (usually `192.168.0.1` or `192.168.1.1`) is great for Ping and HTTP testing

**Option 2: Run Local Test Servers**
```bash
# FTP Server (requires Docker)
docker run -d --name test-ftp -p 21:21 -p 21000-21010:21000-21010 \
  -e FTP_USER=testuser -e FTP_PASS=testpass fauria/vsftpd

# Then add 127.0.0.1 as a workstation with FTP enabled
```

## 🎯 Real-World Deployment

In an actual office environment, you would monitor:

- **Workstations:** Employee computers (e.g., 192.168.1.101-115)
- **Servers:** File servers, domain controllers, mail servers
- **Network Equipment:** Routers, switches, access points
- **Printers:** Network printers with web interfaces
- **IoT Devices:** Security cameras, smart devices

### Example Office Configuration

```
Mail Server     → 192.168.1.50  → Ping, SMTP, POP3
File Server     → 192.168.1.51  → Ping, HTTP, FTP
Domain DNS      → 192.168.1.52  → Ping, DNS
Main Router     → 192.168.1.1   → Ping, HTTP
Print Server    → 192.168.1.60  → Ping, HTTP
```

## 🔧 Troubleshooting

### "Missing required dependency" error

```bash
pip install -r requirements.txt
```

### All pings showing as down

- Verify the IP addresses are correct
- Check that your computer can reach the devices: `ping <ip_address>`
- Some networks block ICMP (ping) packets
- Try running with administrator/sudo privileges

### Email notifications not working

- Verify SMTP credentials are correct
- For Gmail, you may need to use an [App Password](https://support.google.com/accounts/answer/185833)
- Check that SMTP port (usually 587) is not blocked by your firewall
- Test email settings with a simple Python script first

### GUI not launching on macOS

If you get Tkinter errors on macOS:
```bash
brew install python-tk@3.11
```

### Permission denied when binding to ports < 1024

Ports below 1024 require elevated privileges. Either:
- Run with sudo/admin rights (not recommended)
- Configure services to use higher ports (e.g., 8080 instead of 80)

## 📁 Project Structure

```
network-monitor/
├── main.py              # Main application code
├── requirements.txt     # Python dependencies
├── monitor_config.json  # Auto-generated configuration
├── network_monitor.log  # Auto-generated log file
├── LICENSE             # Project license
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

## 🛡️ Security Considerations

- **SMTP passwords are stored in plain text** in `monitor_config.json`
- Keep this file secure with appropriate file permissions
- Consider using environment variables for sensitive credentials in production
- The system requires network access to monitored devices
- No internet connection required unless monitoring external services

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Python's Tkinter for cross-platform compatibility
- Uses dnspython for robust DNS checking
- Requests library for HTTP monitoring
- Inspired by enterprise network monitoring solutions

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review the `network_monitor.log` file for detailed error messages
3. Open an issue on GitHub with:
   - Your operating system
   - Python version (`python --version`)
   - Error messages from the log
   - Steps to reproduce the problem
