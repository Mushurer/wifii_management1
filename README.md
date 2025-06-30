
# WiFi Internet Cafe Management System

A modern web-based system for managing internet access in cafes, hotels, or any public WiFi environment. This system provides session-based internet access control with time limits and user management.

## Features

- 🔐 **Secure User Authentication** - 4-character usernames, 6-character passwords
- ⏰ **Time-based Sessions** - Admin sets time limits for each user session
- 🌐 **Web-based Portal** - Modern, colorful, and interactive GUI
- 👨‍💼 **Admin Panel** - Create sessions, monitor users, change passwords
- 📱 **Mobile Responsive** - Works on phones, tablets, and computers
- 🔒 **SQLite Database** - Secure local data storage
- 🚀 **Cloud Ready** - Deployable on Azure, Replit, or any cloud platform

## How It Works

### For Cloud Deployment (Azure/Replit):
1. Users connect to existing WiFi
2. When they try to browse, they're redirected to your login portal
3. They enter credentials provided by admin
4. System grants/revokes internet access based on time limits

### For Local Deployment (Physical Systems):
1. System can create actual WiFi hotspot (requires Linux with WiFi hardware)
2. Users see and connect to your custom WiFi network
3. Automatic captive portal redirects them to login page

## Installation & Setup

### On Replit (Recommended for Testing):
1. Fork this repository
2. Click "Run" button
3. Access via the provided Replit URL

### On Azure/Cloud:
1. Deploy to Azure App Service or VM
2. Install Python dependencies: `pip install -r requirements.txt`
3. Run: `python main.py`
4. Access via your Azure domain

### Local Installation:
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Usage

### Admin Access:
- URL: `/admin`
- Username: `admin`
- Default Password: `Z@mbezi@1958`
- Features:
  - Create new user sessions
  - Set time limits (minutes)
  - Monitor active sessions
  - Change admin password

### User Access:
- URL: `/` or `/portal`
- Enter 4-character username and 6-character password
- Automatic internet access control based on session time

### WiFi Management:
- URL: `/wifi`
- Configure hotspot settings (for supported environments)
- Monitor system status
- View connected devices

## API Endpoints

- `POST /api/admin/login` - Admin authentication
- `POST /api/admin/create_session` - Create new user session
- `POST /api/user/login` - User authentication
- `GET /api/sessions` - Get active sessions
- `POST /api/sessions/terminate` - Terminate user session
- `GET /api/wifi/status` - Check system status

## File Structure

```
├── main.py                 # Main Flask application
├── requirements.txt        # Python dependencies
├── wifi_cafe.db           # SQLite database (auto-created)
├── templates/             # HTML templates
│   ├── index.html         # User login page
│   ├── admin.html         # Admin panel
│   ├── portal.html        # Captive portal
│   ├── sessions.html      # Session management
│   └── wifi.html          # WiFi configuration
└── README.md              # This file
```

## Security Features

- Password hashing using SHA-256
- Session-based authentication
- Time-based session expiration
- Admin password change capability
- Input validation and sanitization

## Environment Support

### ✅ Fully Supported:
- **Replit**: Perfect for development and testing
- **Azure App Service**: Web portal functionality
- **Linux VMs**: Full hotspot capabilities with proper setup

### ⚠️ Limited Support:
- **Windows**: Web portal only (no hotspot creation)
- **macOS**: Web portal only (no hotspot creation)

### 🔧 Requirements for Full Hotspot Support:
- Linux operating system
- Root/sudo privileges
- WiFi adapter supporting AP mode
- hostapd and dnsmasq packages

## Deployment Notes

### For Cloud Platforms:
The system automatically detects cloud environments and operates in "portal mode" where:
- No actual WiFi hotspot is created
- Users access the portal via web browser
- Internet control is managed through the web interface
- Perfect for existing WiFi networks with captive portal setup

### For Physical Hotspot:
When deployed on appropriate hardware:
- Creates actual WiFi network that appears in phone scans
- Automatic captive portal detection
- Real internet access control via iptables

## Configuration

### Default Settings:
- Port: 5000
- Admin Username: admin
- Admin Password: Z@mbezi@1958
- Database: SQLite (wifi_cafe.db)

### Customization:
- Change admin password through the admin panel
- Modify hotspot name and password in WiFi settings
- Adjust session time limits as needed

## Troubleshooting

### "Can't see WiFi on phone":
- In cloud environments, this is expected - use web portal instead
- For physical systems, ensure proper Linux setup with WiFi hardware

### "Sessions not working":
- Check if admin is logged in
- Verify session hasn't expired
- Check system logs for errors

### "Can't access admin panel":
- Default password: Z@mbezi@1958
- Ensure JavaScript is enabled in browser

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review system logs in the terminal
3. Ensure all requirements are met for your deployment type

## License

This project is designed for educational and commercial use in internet cafes and similar establishments.
