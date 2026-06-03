SERVICE_PATTERNS = [

    # -------------------------------------------------------------------------
    # SSH
    # -------------------------------------------------------------------------
    # OpenSSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    (r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)", "OpenSSH"),
    # Dropbear SSH (common on routers/embedded): "SSH-2.0-dropbear_2022.83"
    (r"SSH-[\d.]+-dropbear[_\s]([\d.]+)", "Dropbear SSH"),
    # libssh: "SSH-2.0-libssh_0.9.6"
    (r"SSH-[\d.]+-libssh[_\s]([\d.]+)", "libssh"),
    # Generic SSH fallback
    (r"SSH-([\d.]+)-", "SSH"),

    # -------------------------------------------------------------------------
    # FTP servers
    # Real banners from research:
    # vsftpd:   "220 (vsFTPd 2.3.5)"
    # ProFTPD:  "220 ProFTPD 1.3.3a Server (Debian) [::ffff:x.x.x.x]"
    # Pure-FTPd:"220---------- Welcome to Pure-FTPd"
    # FileZilla:"220-FileZilla Server 0.9.60 beta"
    # MS FTP:   "220 Microsoft FTP Service (Version 5.0)"
    # wu-ftpd:  "220 host FTP server (Version wu-2.6.2-5) ready"
    # -------------------------------------------------------------------------
    (r"220[- ]\(vsFTPd\s+([\d.]+)\)", "vsftpd"),
    (r"220[- ]vsFTPd\s+([\d.]+)", "vsftpd"),
    (r"220[- ]ProFTPD\s+([\d.]+\w*)", "ProFTPD"),
    (r"220[- ]ProFTPD\b", "ProFTPD"),
    (r"220[-\s]+FileZilla Server\s+([\d.]+)", "FileZilla Server"),
    (r"220[-\s]+FileZilla Server", "FileZilla Server"),
    (r"220[^\r\n]*Pure-FTPd\s+([\d.]+)", "Pure-FTPd"),
    (r"220[^\r\n]*Pure-FTPd", "Pure-FTPd"),
    (r"220[^\r\n]*Microsoft FTP Service[^\r\n]*Version\s+([\d.]+)", "Microsoft FTP"),
    (r"220[^\r\n]*Microsoft FTP Service", "Microsoft FTP"),
    (r"220[^\r\n]*wu-([\d.]+\w*)", "wu-ftpd"),
    (r"220[^\r\n]*FTP server.*Version\s+([\d.]+)", "FTP"),

    # -------------------------------------------------------------------------
    # SMTP servers
    # Real banners:
    # Postfix:  "220 mail.host.com ESMTP Postfix"
    # Exim:     "220 mail.host.com ESMTP Exim 4.95 ..."
    # Sendmail: "220 mail.host.com ESMTP Sendmail 8.14.4/8.14.4"
    # Exchange: "220 mail.host.com Microsoft ESMTP MAIL Service"
    # Haraka:   "220 mail.host.com ESMTP Haraka/2.8.x"
    # -------------------------------------------------------------------------
    (r"220[^\r\n]*ESMTP Exim\s+([\d.]+)", "Exim"),
    (r"220[^\r\n]*ESMTP Exim", "Exim"),
    (r"220[^\r\n]*ESMTP Sendmail\s+([\d./]+)", "Sendmail"),
    (r"220[^\r\n]*ESMTP Sendmail", "Sendmail"),
    (r"220[^\r\n]*Microsoft ESMTP MAIL Service", "Microsoft Exchange"),
    (r"220[^\r\n]*ESMTP Postfix", "Postfix"),
    (r"220[^\r\n]*Postfix", "Postfix"),
    (r"220[^\r\n]*Haraka/([\d.]+)", "Haraka"),
    (r"220[^\r\n]*ESMTP\b", "SMTP"),

    # -------------------------------------------------------------------------
    # POP3 servers
    # Dovecot:  "+OK Dovecot ready"
    # Courier:  "+OK Hello there"
    # UW-IMAP:  "+OK mail.server POP3 ready"
    # -------------------------------------------------------------------------
    (r"\+OK[^\r\n]*Dovecot[^\r\n]*([\d.]+)", "Dovecot POP3"),
    (r"\+OK[^\r\n]*Dovecot", "Dovecot POP3"),
    (r"\+OK[^\r\n]*Courier[^\r\n]*([\d.]+)", "Courier POP3"),
    (r"\+OK[^\r\n]*Courier", "Courier POP3"),
    (r"\+OK[^\r\n]*POP3", "POP3"),

    # -------------------------------------------------------------------------
    # IMAP servers
    # Dovecot:  "* OK [CAPABILITY ...] Dovecot ready"
    # Courier:  "* OK IMAP4rev1 2004.352 at"
    # Cyrus:    "* OK Cyrus IMAP4 v2.3.x"
    # -------------------------------------------------------------------------
    (r"\* OK[^\r\n]*Dovecot[^\r\n]*([\d.]+)", "Dovecot IMAP"),
    (r"\* OK[^\r\n]*Dovecot", "Dovecot IMAP"),
    (r"\* OK[^\r\n]*Cyrus IMAP[^\r\n]*([\d.x]+)", "Cyrus IMAP"),
    (r"\* OK[^\r\n]*Courier-IMAP[^\r\n]*([\d.]+)", "Courier IMAP"),
    (r"\* OK IMAP4rev1", "IMAP"),
    (r"\* OK[^\r\n]*IMAP", "IMAP"),

    # -------------------------------------------------------------------------
    # Web servers — HTTP Server header
    # Must be before generic fallback
    # -------------------------------------------------------------------------
    # Apache httpd: "Server: Apache/2.4.41 (Ubuntu)"
    (r"Server:\s*Apache/([\d.]+)", "Apache httpd"),
    (r"Server:\s*Apache\b", "Apache httpd"),
    # nginx: "Server: nginx/1.18.0"
    (r"Server:\s*nginx/([\d.]+)", "nginx"),
    (r"Server:\s*nginx\b", "nginx"),
    # Microsoft IIS: "Server: Microsoft-IIS/10.0"
    (r"Server:\s*Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
    # LiteSpeed: "Server: LiteSpeed"
    (r"Server:\s*LiteSpeed", "LiteSpeed"),
    # Caddy: "Server: Caddy"
    (r"Server:\s*Caddy/([\d.]+)", "Caddy"),
    (r"Server:\s*Caddy\b", "Caddy"),
    # Apache Tomcat / Coyote
    (r"Server:\s*Apache-Coyote/([\d.]+)", "Apache Tomcat"),
    (r"Server:\s*Apache Tomcat/([\d.]+)", "Apache Tomcat"),
    # Jetty: "Server: Jetty(9.4.z-SNAPSHOT)"
    (r"Server:\s*Jetty\(([\d.]+)", "Jetty"),
    (r"Server:\s*Jetty\b", "Jetty"),
    # Gunicorn: "Server: gunicorn/20.1.0"
    (r"Server:\s*gunicorn/([\d.]+)", "Gunicorn"),
    (r"Server:\s*gunicorn\b", "Gunicorn"),
    # Werkzeug (Flask dev server)
    (r"Server:\s*Werkzeug/([\d.]+)", "Werkzeug/Flask"),
    # Uvicorn (FastAPI) — catches our own server
    (r"Server:\s*uvicorn\b", "uvicorn"),
    # Node.js / Express
    (r"X-Powered-By:\s*Express", "Express/Node.js"),
    # OpenResty (nginx + Lua)
    (r"Server:\s*openresty/([\d.]+)", "OpenResty"),
    (r"Server:\s*openresty\b", "OpenResty"),
    # Cowboy (Erlang)
    (r"Server:\s*Cowboy", "Cowboy"),
    # Tengine (Alibaba nginx fork)
    (r"Server:\s*Tengine/([\d.]+)", "Tengine"),
    (r"Server:\s*Tengine\b", "Tengine"),
    # HAProxy
    (r"Server:\s*haproxy/([\d.]+)", "HAProxy"),

    # -------------------------------------------------------------------------
    # Embedded / Router / IoT web servers
    # Common on home routers and IoT devices
    # -------------------------------------------------------------------------
    (r"Server:\s*lighttpd/([\d.]+)", "lighttpd"),
    (r"Server:\s*lighttpd\b", "lighttpd"),
    (r"Server:\s*GoAhead/([\d.]+)", "GoAhead"),
    (r"Server:\s*GoAhead-Webs", "GoAhead"),
    (r"Server:\s*GoAhead\b", "GoAhead"),
    (r"Server:\s*uhttpd/([\d.]+)", "uhttpd"),
    (r"Server:\s*uhttpd\b", "uhttpd"),
    (r"Server:\s*mini_httpd/([\d.]+)", "mini_httpd"),
    (r"Server:\s*Boa/([\d.]+)", "Boa httpd"),
    # RomPager — old/vulnerable, found on many DSL routers
    (r"Server:\s*RomPager/([\d.]+)", "RomPager"),
    (r"Server:\s*RomPager\b", "RomPager"),
    # MikroTik RouterOS
    (r"RouterOS/([\d.]+)", "MikroTik RouterOS"),
    (r"RouterOS\b", "MikroTik RouterOS"),
    # Cisco
    (r"Server:\s*cisco-IOS\b", "Cisco IOS"),

    # -------------------------------------------------------------------------
    # Databases
    # -------------------------------------------------------------------------
    # MySQL / MariaDB
    # Real banner: "5.7.38-MySQL Community Server"
    # MariaDB:     "5.5.5-10.6.11-MariaDB-2~ubuntu"
    (r"([\d.]+)-MariaDB", "MariaDB"),
    (r"([\d.]+)-MySQL", "MySQL"),
    (r"mysql_native_password", "MySQL"),
    # PostgreSQL — appears in error/SSL rejection banners
    (r"PostgreSQL\s+([\d.]+)", "PostgreSQL"),
    (r"FATAL:.*PostgreSQL", "PostgreSQL"),
    # Microsoft SQL Server
    (r"Microsoft SQL Server\s+([\d.]+)", "Microsoft SQL Server"),
    (r"Microsoft SQL Server", "Microsoft SQL Server"),
    # Oracle DB
    (r"Oracle.*Database.*(\d+[cg])", "Oracle Database"),
    # Redis
    # Real banner from research: "redis_version:2.8.13" in INFO response
    # Redis doesn't send a banner on connect — it responds to commands
    # "-ERR" is the unauthenticated response, "redis_version" after INFO
    (r"redis_version:([\d.]+)", "Redis"),
    (r"-ERR.*Redis", "Redis"),
    (r"-NOAUTH", "Redis"),
    # Memcached: "VERSION 1.6.17"
    (r"VERSION\s+([\d.]+)\r\n", "Memcached"),
    # MongoDB — sends a binary handshake but version sometimes visible
    (r"MongoDB\s+([\d.]+)", "MongoDB"),
    (r"ismaster|isMaster", "MongoDB"),
    # Elasticsearch — HTTP JSON response
    (r'"cluster_name"\s*:', "Elasticsearch"),
    (r'"version"\s*:\s*\{\s*"number"\s*:\s*"([\d.]+)"', "Elasticsearch"),
    # CouchDB
    (r'"couchdb"\s*:', "CouchDB"),
    # InfluxDB
    (r"X-Influxdb-Version:\s*([\d.]+)", "InfluxDB"),

    # -------------------------------------------------------------------------
    # OpenSSL / TLS info — sometimes visible in banners
    # -------------------------------------------------------------------------
    (r"OpenSSL/([\d.]+\w*)", "OpenSSL"),

    # -------------------------------------------------------------------------
    # SMB / Samba / Windows file sharing
    # -------------------------------------------------------------------------
    (r"Samba\s+([\d.]+)", "Samba"),
    (r"Samba\b", "Samba"),
    (r"Windows.*SMB", "SMB"),

    # -------------------------------------------------------------------------
    # VNC — Remote desktop
    # Banner: "RFB 003.008" — RFB is the VNC protocol
    # -------------------------------------------------------------------------
    (r"RFB\s+([\d.]+)", "VNC"),

    # -------------------------------------------------------------------------
    # Telnet / remote access
    # -------------------------------------------------------------------------
    (r"Cisco.*IOS.*Version\s+([\d.()A-Za-z]+)", "Cisco IOS"),
    (r"Linux\s+[\w.-]+\s+[\d.]+.*login:", "Linux Telnet"),
    (r"Welcome to Microsoft Telnet Service", "Microsoft Telnet"),

    # -------------------------------------------------------------------------
    # Message brokers
    # -------------------------------------------------------------------------
    # RabbitMQ AMQP — binary protocol, sometimes version in error response
    (r"AMQP", "RabbitMQ/AMQP"),
    (r"RabbitMQ\s+([\d.]+)", "RabbitMQ"),
    # ActiveMQ
    (r"ActiveMQ\s+([\d.]+)", "Apache ActiveMQ"),
    (r"ActiveMQ\b", "Apache ActiveMQ"),

    # -------------------------------------------------------------------------
    # DNS — should not appear on TCP/53 banners normally
    # but some implementations identify themselves
    # -------------------------------------------------------------------------
    (r"BIND\s+([\d.]+)", "ISC BIND"),
    (r"dnsmasq-([\d.]+)", "dnsmasq"),
    (r"PowerDNS\s+([\d.]+)", "PowerDNS"),

    # -------------------------------------------------------------------------
    # LDAP
    # -------------------------------------------------------------------------
    (r"OpenLDAP\s+([\d.]+)", "OpenLDAP"),

    # -------------------------------------------------------------------------
    # Docker / container infrastructure
    # -------------------------------------------------------------------------
    (r"Docker/([\d.]+)", "Docker"),
    (r'"ServerVersion"\s*:\s*"([\d.]+)"', "Docker"),

    # -------------------------------------------------------------------------
    # Kubernetes API server
    # -------------------------------------------------------------------------
    (r'"gitVersion"\s*:\s*"v([\d.]+)"', "Kubernetes"),

    # -------------------------------------------------------------------------
    # CUPS (printing)
    # -------------------------------------------------------------------------
    (r"Server:\s*CUPS/([\d.]+)", "CUPS"),
    (r"CUPS/([\d.]+)", "CUPS"),

    # -------------------------------------------------------------------------
    # Printers / IoT devices
    # -------------------------------------------------------------------------
    (r"Printer", "Network Printer"),
    (r"EPSON", "Epson Printer"),
    (r"HP.*LaserJet", "HP LaserJet"),

    # -------------------------------------------------------------------------
    # Generic HTTP Server header fallback
    # Catches anything with a Server: header that didn't match above
    # The captured group is the full server string
    # -------------------------------------------------------------------------
    (r"Server:\s*([^\r\n]{2,64})", "HTTP Server"),
]
