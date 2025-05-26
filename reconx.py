#!/usr/bin/env python3
import os
import asyncwhois
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.text import Text
from wappalyzer import analyze as wappalyzer_analyze
import requests
import urllib3
import json
import urllib.parse

# Suppress InsecureRequestWarning for self-signed certificates etc.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Embedded wordlist. For very large lists, consider an external file.
COMMON_SUBDOMAINS = [
    # Common Web & Mail
    'www', 'www0', 'www1', 'www2', 'www3', 'www4', 'wwwhost', 'web', 'website', 'm', 'mobile', 'mobi', 'mail', 'email', 'smtp', 'pop', 'pop3', 'imap', 'webmail', 'owa', 'exchange', 'outlook', 'webaccess', 'mailserver', 'smtpout', 'smtpin', 'mx', 'ftp', 'sftp', 'ssh', 'telnet', 'secureftp',
    # Nameservers
    'ns', 'ns0', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9', 'dns', 'dns0', 'dns1', 'dns2', 'dns3', 'dns4', 'pdns', 'bind', 'powerdns', 'nsd', 'knot',
    # Admin & Control Panels
    'admin', 'administrator', 'adm', 'root', 'system', 'panel', 'control', 'cp', 'cpanel', 'whm', 'plesk', 'directadmin', 'webmin', 'usermin', 'manage', 'manager',
    'dashboard', 'config', 'settings', 'webadmin', 'adminconsole', 'console', 'server-admin', 'admin-panel', 'controlpanel', 'sysadmin', 'remoteadmin', 'serveradmin',
    # Development & Staging
    'dev', 'development', 'develop', 'devel', 'stage', 'staging', 'stg', 'test', 'testing', 'tst', 'uat', 'qa', 'sandbox', 'demo', 'example',
    'preview', 'beta', 'alpha', 'gamma', 'rc', 'canary', 'local', 'localhost', 'dev-server', 'test-server', 'stage-server',
    'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'old', 'new', 'classic', 'current', 'next', 'previous', 'latest', 'stable',
    'app-dev', 'app-test', 'app-staging', 'app-prod', 'web-dev', 'web-test', 'web-staging', 'web-prod', 'preprod', 'pre-prod', 'prototype', 'temp', 'tmp', 'builds', 'nightly',
    # API & Services
    'api', 'api-dev', 'api-test', 'api-stage', 'api-prod', 'api-internal', 'api-external', 'api-gateway', 'api-v1', 'api-v2', 'api-v3', 'api-v4', 'api-v5',
    'service', 'services', 'app', 'apps', 'core', 'edge', 'gateway', 'gw', 'microservice', 'backend', 'frontend',
    'rest', 'soap', 'rpc', 'grpc', 'graphql', 'ws', 'wss', 'mqtt', 'amqp', 'xmpp', 'sip', 'rtmp', 'webrtc', 'push', 'events', 'stream', 'streaming', 'apigw', 'eventsource', 'pubsub', 'dataapi', 'userapi', 'authapi',
    # Content & Assets
    'blog', 'forum', 'forums', 'community', 'news', 'press', 'updates', 'shop', 'store', 'cart', 'checkout', 'catalog', 'products', 'services-info',
    'files', 'assets', 'static', 'cdn', 'images', 'img', 'media', 'video', 'audio', 'music', 'download', 'downloads', 'dl', 'mirror',
    'content', 'data', 'db', 'database', 'sql', 'mysql', 'mariadb', 'postgres', 'postgresql', 'mongo', 'mongodb', 'redis', 'memcached', 'memcache',
    'elasticsearch', 'es', 'solr', 'influxdb', 'prometheus', 'graphite', 'cassandra', 'couchbase', 'neo4j', 'rethinkdb', 'dynamodb',
    'backup-db', 'dev-db', 'stage-db', 'prod-db', 'sql01', 'sql02', 'mongo01', 'mongo02', 'db-master', 'db-slave', 'db-replica', 'usercontent', 'static-assets', 'mediafiles', 'docs-assets', 'dbadmin',
    # Support & Documentation
    'support', 'help', 'helpdesk', 'ticket', 'tickets', 'otrs', 'osticket', 'docs', 'documentation', 'developer-docs', 'customer-support', 'wiki', 'faq', 'howto', 'manual', 'knowledgebase', 'kb', 'guides', 'tutorials', 'statuspage', 'feedback',
    # Security & Network
    'secure', 'ssl', 'tls', 'vpn', 'firewall', 'fw', 'proxy', 'router', 'internal', 'intranet', 'extranet', 'private', 'public', 'dmz', 'lan', 'wan',
    'login', 'logon', 'signin', 'signout', 'logout', 'signup', 'register', 'auth', 'sso', 'oauth', 'oidc', 'saml', 'id', 'identity', 'idp', 'iam',
    'ldap', 'radius', 'kerberos', 'ad', 'pki', 'ca', 'certs', 'certificates', 'cert', 'vault', 'secrets', 'keycloak', 'okta', 'auth0',
    'honeypot', 'ids', 'ips', 'waf', 'nessus', 'qualys', 'burp', 'metasploit', 'openvas', 'authn', 'authz', 'vpn-gw', 'siem', 'soc',
    # Monitoring & Logging
    'status', 'monitor', 'monitoring', 'nagios', 'zabbix', 'icinga', 'grafana', 'kibana', 'elk', 'efk', 'loki', 'splunk', 'graylog', 'syslog', 'rsyslog', 'fluentd',
    'logs', 'logging', 'logserver', 'loghost', 'metrics', 'tracing', 'alert', 'alerts', 'uptime', 'stats-internal', 'log-internal', 'alertmanager', 'logcollector',
    # Backup & Storage
    'backup', 'archive', 'storage', 'nas', 'san', 'cloud', 's3', 's3-website', 'blob', 'nfs', 'cifs', 'glusterfs', 'ceph', 'minio', 'fileshare', 'datastore', 'archive-server', 'backup-storage', 'backups', 'objectstore', 'object-storage', 'filestore',
    # Specific Technologies / Platforms / CI-CD
    'jira', 'confluence', 'bamboo', 'bitbucket', 'jenkins', 'ci', 'cd', 'build', 'deploy', 'gitlab', 'git', 'gitea', 'gogs', 'svn', 'cvs', 'mercurial', 'source', 'repo', 'nexus', 'artifactory', 'sonarqube', 'spinnaker', 'teamcity', 'drone',
    'docker', 'kubernetes', 'k8s', 'k3s', 'openshift', 'rancher', 'swarm', 'mesos', 'nomad', 'container', 'registry', 'harbor', 'ecr', 'gcr', 'acr', 'lambda', 'ec2', 'rds', 'eks', 'gke', 'aks', 'azurewebsites',
    'wordpress', 'wp', 'drupal', 'joomla', 'magento', 'ghost', 'typo3', 'sharepoint', 'moodle', 'blackboard', 'canvas',
    'teams', 'zoom', 'webex', 'slack', 'mattermost', 'rocketchat', 'discord', 'discourse', 'phpmyadmin', 'pgadmin', 'adminer',
    'ansible', 'puppet', 'chef', 'salt', 'terraform', 'vagrant', 'packer', 'docker-registry',
    # Geographic / Regional / Datacenter
    'us', 'uk', 'gb', 'eu', 'de', 'fr', 'jp', 'cn', 'in', 'ca', 'au', 'br', 'ru', 'asia', 'europe', 'america', 'africa', 'oceania',
    'east', 'west', 'north', 'south', 'central', 'us-east-1', 'us-west-2', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1',
    'dc1', 'dc2', 'dc3', 'datacenter', 'cluster', 'node', 'node01', 'node02', 'region', 'zone', 'site', 'colo', 'dr', 'failover', 'primary', 'secondary', 'active', 'passive',
    # Financial & E-commerce
    'payment', 'payments', 'pay', 'billing', 'invoice', 'finance', 'investors', 'ir', 'accounting', 'payroll', 'tax', 'subscription', 'donate',
    'affiliate', 'partnernet', 'ads', 'adserver', 'analytics', 'ga', 'piwik', 'matomo', 'click', 'track', 'tracking', 'billing-api', 'payment-gateway', 'shop-api', 'affiliates', 'tracking-api',
    # Other common prefixes/services
    'autodiscover', 'calendar', 'chat', 'conference', 'crm', 'erp', 'hr', 'jobs', 'careers', 'legal', 'marketing', 'salesforce', 'hubspot', 'mailchimp',
    'newsletter', 'office', 'owa.mail', 'owa.exchange', 'partner', 'partners', 'portal', 'customer-portal', 'developer-portal', 'employee-portal', 'remote', 'reports', 'school', 'search', 'server',
    'stats', 'survey', 'talk', 'upload', 'webdisk', 'webinar', 'work', 'xml', 'json', 'yaml', 'go', 'my', 'me', 'io', 'mailgate', 'smtp-gateway', 'selfservice', 'appstore', 'download-center', 'learning', 'training', 'api-docs', 'status-api',
    'remote.access', 'secure.login', 'vpn.access', 'dev.api', 'test.api', 'staging.api', 'prod.api', 'prod', 'production', 'master', 'main', 'release',
    'lab', 'labs', 'research', 'devops', 'sysops', 'netops', 'secops', 'cloudops', 'sre', 'platform', 'infra', 'infrastructure',
    'localdomain', 'internaldomain', 'devdomain', 'testdomain', 'corp', 'corporate', 'internal-network',
    # Less common but sometimes found / Generic words / Combinations
    'assets01', 'assets02', 'backup-01', 'beta-site', 'cdn01', 'dev-01', 'dev-app', 'dev-db01', 'dev-web01', 'dev01', 'test01', 'stage01', 'prod01', 'web01', 'web02', 'app01', 'app02', 'db01', 'db02',
    'emailgw', 'files01', 'git01', 'internal-apps', 'intranet-apps', 'legacy-sys', 'log01', 'log02',
    'mail01', 'mail02', 'media01', 'metrics01', 'mobile-gw', 'monitor01', 'new-app', 'old-app', 'old-site',
    'priv', 'pub', 'qa01', 'qa-app', 'report-server', 'sandbox01', 'securegw', 'securemail', 'securepay',
    'stage01', 'stage-app', 'static01', 'test01', 'test-app', 'uat01', 'uat-app', 'user-auth', 'utility-server',
    'vendor-portal', 'voicegw', 'web01', 'web02', 'web-app01', 'web-gw', 'weblog01', 'webmail01', 'workplace-portal',
    # Single letter (can be very noisy for internet-wide scans, use with caution or for specific targets)
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    # Common misspellings or variations (examples - can be extensive)
    'supportt', 'devolopment', 'adm1n', 'web-maill', 'cpanel1', 'testting', 'api-v01', 'bl0g', 'securee', 'monitorring', 'backupp', 'jenkinss', 'wordpres', 'us-eest-1', 'paymeny', 'autodiscoverr'
]

# Common files and directories for enumeration
COMMON_PATHS = [
    # Common directories
    "admin", "administrator", "login", "logon", "wp-admin", "wp-login.php", "controlpanel", "cpanel", "manage",
    "moderator", "webadmin", "adminpanel", "user", "users", "account", "accounts", "guest", "test", "tmp",
    "temp", "backup", "backups", "dev", "staging", "prod", "production", "includes", "assets", "static",
    "js", "css", "img", "images", "files", "uploads", "downloads", "scripts", "cgi-bin", "api", "app",
    "config", "configs", "settings", "db", "database", "sql", "data", "private", "secret", "logs", "archive",
    "old", "includes", "core", "lib", "vendor", "src", "public", "phpmyadmin", "pma", "webmail", "roundcube",
    "squirrelmail", "owa", "exchange", "autodiscover", "remote", "portal", "intranet", "support", "docs",
    "documentation", "examples", "samples", "test-page.html", "index.php", "index.html", "default.html",
    "default.asp", "main.html", "home.html", "readme.html", "license.html", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "humans.txt", "security.txt", ".htaccess", ".htpasswd", ".env", ".env.example",
    ".env.local", ".env.dev", ".env.prod", "config.js", "config.json", "settings.py", "local_settings.py",
    "web.config", "appsettings.json", "docker-compose.yml", "Dockerfile", ".git/config", ".git/HEAD", ".svn/entries",
    ".DS_Store", "Thumbs.db", "error_log", "access_log", "phpinfo.php", "test.php", "status", "server-status",
    "server-info", "aspnet_client", "_ignition/health-check", "telescope", "horizon", "nova-api", "swagger",
    "swagger-ui.html", "api-docs", "graphql", "v1", "v2", "v3", "_next", "_nuxt", "_static", "_app",
    # Common backup file extensions
    "backup.zip", "backup.tar.gz", "backup.sql", "site.zip", "database.sql.zip", "db.zip",
    # Common sensitive files
    "id_rsa", "id_dsa", "credentials", "secrets.txt", "users.txt", "passwords.txt", "wp-config.php.bak",
    "config.php.old", "composer.lock", "yarn.lock", "package-lock.json"
]

def enumerate_subdomains_from_dns(domain, console):
    """Query DNS records (MX, NS, SOA, SRV) and try AXFR for subdomains."""
    discovered_subdomains = set()
    base_domain = domain.lower() # Ensure consistent comparison

    console.print(f"\n[b]--- DNS-Based Subdomain Enumeration for {base_domain} ---[/b]")

    # 1. Query common record types
    record_types_to_check = ['MX', 'NS', 'SOA', 'SRV'] # CNAME is tricky here, TXT needs parsing
    console.print("[info]Querying common DNS record types (MX, NS, SOA, SRV)...[/info]")
    for r_type in record_types_to_check:
        try:
            answers = dns.resolver.resolve(base_domain, r_type)
            for rdata in answers:
                hostname_to_check = None
                if r_type == 'MX':
                    hostname_to_check = str(rdata.exchange).rstrip('.').lower()
                elif r_type == 'NS':
                    hostname_to_check = str(rdata.target).rstrip('.').lower()
                elif r_type == 'SOA':
                    hostname_to_check = str(rdata.mname).rstrip('.').lower()
                    # rname is an email, but mname is a nameserver
                elif r_type == 'SRV':
                    hostname_to_check = str(rdata.target).rstrip('.').lower()
                
                if hostname_to_check:
                    if hostname_to_check.endswith(f".{base_domain}") or hostname_to_check == base_domain:
                        if hostname_to_check != base_domain: # We want subdomains
                             discovered_subdomains.add(hostname_to_check)
                             console.print(f"  [dim]Found potential subdomain from {r_type}: {hostname_to_check}[/dim]")
        except dns.resolver.NoAnswer:
            console.print(f"  [dim]No {r_type} records found for {base_domain}.[/dim]")
        except dns.resolver.NXDOMAIN:
            console.print(f"  [bold red]Domain {base_domain} does not exist (NXDOMAIN).[/bold red]")
            return list(discovered_subdomains) # No point continuing
        except dns.resolver.Timeout:
            console.print(f"  [red]DNS query for {r_type} records for {base_domain} timed out.[/red]")
        except dns.exception.DNSException as e:
            console.print(f"  [red]DNS query for {r_type} failed: {type(e).__name__} - {e}[/red]")
            
    # 2. Attempt DNS Zone Transfer (AXFR)
    console.print("\n[info]Attempting DNS Zone Transfer (AXFR)...[/info]")
    ns_records = []
    try:
        ns_answers = dns.resolver.resolve(base_domain, 'NS')
        ns_records = [str(rdata.target).rstrip('.') for rdata in ns_answers]
    except Exception as e:
        console.print(f"  [yellow]Could not resolve NS records for AXFR: {e}[/yellow]")

    if not ns_records:
        console.print("  [yellow]No nameservers found to attempt AXFR.[/yellow]")

    for ns_server_host in ns_records:
        console.print(f"  [dim]Attempting AXFR from nameserver: {ns_server_host}[/dim]")
        ns_ip = None
        try:
            # Resolve NS hostname to IP
            ip_answers = dns.resolver.resolve(ns_server_host, 'A')
            if ip_answers:
                ns_ip = ip_answers[0].to_text()
            else: # Try AAAA if A fails
                ip_answers = dns.resolver.resolve(ns_server_host, 'AAAA')
                if ip_answers:
                    ns_ip = ip_answers[0].to_text()
        except Exception as e:
            console.print(f"    [yellow]Could not resolve IP for nameserver {ns_server_host}: {e}[/yellow]")
            continue

        if not ns_ip:
            console.print(f"    [yellow]No IP address found for nameserver {ns_server_host}. Skipping AXFR.[/yellow]")
            continue
        
        console.print(f"    [dim]Using IP {ns_ip} for {ns_server_host} for AXFR attempt on {base_domain}[/dim]")
        try:
            # Setting timeout for XFR query
            xfr_timeout = 5 # seconds
            zone_data = dns.query.xfr(ns_ip, base_domain, timeout=xfr_timeout)
            
            zone = dns.zone.from_xfr(zone_data, origin=base_domain)
            
            for name, node in zone.nodes.items():
                if str(name) == '@': 
                    full_hostname = base_domain
                else:
                    full_hostname = (str(name) + "." + base_domain).rstrip('.').lower()

                if full_hostname.endswith(f".{base_domain}") and full_hostname != base_domain:
                    discovered_subdomains.add(full_hostname)
                    console.print(f"    [bright_green]Found via AXFR on {ns_server_host}: {full_hostname}[/bright_green]")
            console.print(f"    [green]AXFR successful from {ns_server_host}![/green]")

        except dns.exception.FormError:
            console.print(f"    [yellow]AXFR from {ns_server_host} failed: Server misconfiguration or not an authoritative server (FormError).[/yellow]")
        except dns.resolver.Timeout:
            console.print(f"    [yellow]AXFR from {ns_server_host} timed out after {xfr_timeout}s.[/yellow]")
        except dns.query.TransferError as e: 
            console.print(f"    [yellow]AXFR from {ns_server_host} failed: Transfer error - {e}. (Often means 'REFUSED')[/yellow]")
        except Exception as e:
            console.print(f"    [red]AXFR from {ns_server_host} failed: {type(e).__name__} - {e}[/red]")
            
    if not discovered_subdomains:
        console.print(f"\n[yellow]No subdomains found through basic DNS record queries or AXFR for {base_domain}.[/yellow]")
    else:
        console.print(f"\n[b]Discovered {len(discovered_subdomains)} unique potential subdomains via DNS methods:[/b]")
            
    return sorted(list(discovered_subdomains))

def enumerate_subdomains_from_ct(domain, console: Console):
    """Query Certificate Transparency logs (crt.sh) for subdomains."""
    console.print(f"\n[info]Querying Certificate Transparency logs for {domain} via crt.sh...[/info]")
    subdomains = set()
    try:
        # The %. is important to get subdomains of the target domain
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=45) # Increased timeout for potentially large/slow responses
        response.raise_for_status() # Raise an exception for HTTP errors
        
        raw_data = []
        try:
            # crt.sh can return a stream of JSON objects or a single list
            # We'll try to handle both by attempting to decode line by line if it's not a single valid JSON array
            full_response_text = response.text
            if full_response_text.strip().startswith('[') and full_response_text.strip().endswith(']'):
                 raw_data = json.loads(full_response_text)
            else: # Try line-by-line if it's a stream of JSON objects
                for line in full_response_text.splitlines():
                    if line.strip():
                        raw_data.append(json.loads(line))
        except json.JSONDecodeError:
            console.print(f"  [yellow]crt.sh returned non-JSON or malformed JSON data for {domain}. This might indicate no results or an issue with the service.[/yellow]")
            return []

        if not raw_data:
            console.print(f"  [yellow]No Certificate Transparency log entries found for {domain} via crt.sh.[/yellow]")
            return []

        for entry in raw_data:
            name_value = entry.get('name_value', '')
            if name_value:
                names = name_value.split('\n') # crt.sh uses \n in name_value for multiple SANs
                for name in names:
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") and name != domain and not name.startswith('*.'):
                        subdomains.add(name)
            
            common_name = entry.get('common_name', '').strip().lower()
            if common_name and common_name.endswith(f".{domain}") and common_name != domain and not common_name.startswith('*.'):
                subdomains.add(common_name)

        if not subdomains:
            console.print(f"  [yellow]No valid subdomains extracted from CT logs for {domain}, though entries might have been found.[/yellow]")

    except requests.exceptions.Timeout:
        console.print(f"  [red]Timeout while querying crt.sh for {domain}.[/red]")
    except requests.exceptions.HTTPError as e:
        console.print(f"  [red]HTTP error querying crt.sh for {domain}: {e.response.status_code if e.response else 'Unknown Status'}[/red]")
    except requests.exceptions.RequestException as e:
        console.print(f"  [red]Error querying crt.sh for {domain}: {e}[/red]")
    except Exception as e:
        console.print(f"  [red]An unexpected error occurred during CT log enumeration for {domain}: {e}[/red]")
        
    found_subdomains_list = sorted(list(subdomains))
    if found_subdomains_list:
        console.print(f"  [green]Discovered {len(found_subdomains_list)} potential subdomain(s) from CT logs.[/green]")
    return found_subdomains_list

def enumerate_subdomains_intelligence(domain, console: Console):
    """Enumerate subdomains using DNS, CT Logs, and check liveness."""
    console.print(f"\n[b]--- Intelligence Subdomain Enumeration for {domain} (DNS & CT Logs) ---[/b]")
    
    all_potential_subdomains = set()

    # 1. DNS-based enumeration
    console.print("\n[b]-> Performing DNS-based subdomain enumeration...[/b]")
    dns_subdomains = enumerate_subdomains_from_dns(domain, console) 
    if dns_subdomains:
        console.print(f"  [green]DNS method found {len(dns_subdomains)} potential subdomains.[/green]")
        all_potential_subdomains.update(dns_subdomains)
    else:
        console.print("  [yellow]DNS method found no subdomains.[/yellow]")

    # 2. Certificate Transparency (CT) log enumeration
    console.print("\n[b]-> Performing Certificate Transparency (CT) log enumeration...[/b]")
    ct_subdomains = enumerate_subdomains_from_ct(domain, console) 
    if ct_subdomains:
        console.print(f"  [green]CT Log method found {len(ct_subdomains)} potential subdomains.[/green]")
        all_potential_subdomains.update(ct_subdomains)
    else:
        console.print("  [yellow]CT Log method found no subdomains.[/yellow]")

    if not all_potential_subdomains:
        console.print(f"\n[yellow]Intelligence scan found no potential subdomains for {domain} from any source.[/yellow]")
        return

    sorted_subdomains = sorted(list(all_potential_subdomains))
    console.print(f"\n[info]Total unique potential subdomains found by Intelligence scan: {len(sorted_subdomains)}[/info]")

    console.print("\n[b]--- Checking Liveness of Discovered Intelligence Subdomains ---[/b]")
    live_subdomains_intelligence = []
    if not sorted_subdomains:
        console.print("[yellow]No subdomains to check for liveness.[/yellow]")
    else:
        for sub_idx, sub in enumerate(sorted_subdomains):
            console.print(f"  [dim]Checking ({sub_idx+1}/{len(sorted_subdomains)}): {sub}[/dim]")
            try:
                dns.resolver.resolve(sub, 'A') 
                for protocol in ['http', 'https']:
                    try:
                        url = f"{protocol}://{sub}"
                        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
                        console.print(f"    [green]LIVE: {url} (Status: {response.status_code})[/green]")
                        live_subdomains_intelligence.append(url)
                        break 
                    except requests.exceptions.ConnectionError:
                        pass 
                    except requests.exceptions.Timeout:
                        console.print(f"    [yellow]TIMEOUT: {url}[/yellow]")
                    except requests.exceptions.RequestException as e:
                        if "SSL" in str(e) or "socket" in str(e).lower() or "protocol" in str(e).lower():
                             console.print(f"    [yellow]Connection issue with {url}: {type(e).__name__}. (May not be an HTTP/S service or SSL/protocol issue).[/yellow]")
                        else:
                            console.print(f"    [yellow]Error checking {url}: {type(e).__name__}[/yellow]")
                        pass 
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                console.print(f"    [dim]Subdomain {sub} did not resolve to an IP.[/dim]")
            except dns.resolver.Timeout:
                console.print(f"    [red]DNS resolution timed out for {sub}.[/red]")
            except Exception as e:
                console.print(f"    [red]Error checking liveness for {sub}: {e}[/red]")

    if not live_subdomains_intelligence:
        console.print("\n[yellow]Intelligence scan complete: No live web servers found on the discovered subdomains.[/yellow]")
    else:
        console.print(f"\n[green]Intelligence scan complete: Found {len(live_subdomains_intelligence)} live web server(s).[/green]")
    return live_subdomains_intelligence

def enumerate_files_directories(base_url, console: Console, wordlist_to_use):
    """Enumerate files/directories on a base URL using a wordlist."""
    console.print(f"\n[b]--- File & Directory Enumeration for {base_url} ---[/b]")
    console.print(f"Using a wordlist of {len(wordlist_to_use)} paths.")

    if not base_url.startswith(('http://', 'https://')):
        console.print(f"  [yellow]Base URL '{base_url}' does not start with http:// or https://. Please provide a full URL.[/yellow]")
        console.print(f"  [dim]Example: http://{base_url} or https://{base_url}[/dim]")
        return

    found_resources = []
    interesting_status_codes = {200, 204, 301, 302, 307, 308, 401, 403, 500}

    # Ensure base_url ends with a slash if it's just a domain, to correctly append paths
    parsed_url = urllib.parse.urlparse(base_url)
    if not parsed_url.path or parsed_url.path == '/':
        if not base_url.endswith('/'):
            base_url_to_join = base_url + '/'
        else:
            base_url_to_join = base_url
    else: # If base_url already has a path, join carefully
         base_url_to_join = base_url if base_url.endswith('/') else base_url + '/'

    with console.status("[cyan]Scanning paths...[/cyan]", spinner="dots") as status:
        for i, path in enumerate(wordlist_to_use):
            # Remove leading slash from path if present, as base_url_to_join will have one
            path_to_check = path.lstrip('/') 
            url_to_check = urllib.parse.urljoin(base_url_to_join, path_to_check)
            status.update(f"[cyan]Scanning paths... ({i+1}/{len(wordlist_to_use)}) Checking: {url_to_check}[/cyan]")
            try:
                response = requests.get(url_to_check, timeout=5, verify=False, allow_redirects=False, headers={'User-Agent': 'ReconX/0.6 FileEnum'})
                if response.status_code in interesting_status_codes:
                    status_style = "green" if response.status_code == 200 else "yellow"
                    if response.status_code in [301, 302, 307, 308] and 'Location' in response.headers:
                        console.print(f"  [{status_style}]{response.status_code}: {url_to_check} -> {response.headers['Location']}[/{status_style}]")
                    else:
                        console.print(f"  [{status_style}]{response.status_code}: {url_to_check}[/{status_style}]")
                    found_resources.append({'url': url_to_check, 'status': response.status_code, 'location': response.headers.get('Location')})
            except requests.exceptions.Timeout:
                console.print(f"  [red]TIMEOUT: {url_to_check}[/red]")
            except requests.exceptions.ConnectionError:
                # This can be noisy if the base host is down, so only print if it's not the first few checks
                if i > 10: # Heuristic to avoid flooding if base domain is dead
                    console.print(f"  [red]CONNECTION ERROR: {url_to_check}[/red]")
            except requests.exceptions.RequestException as e:
                console.print(f"  [red]ERROR: {url_to_check} ({type(e).__name__})[/red]")
    
    if found_resources:
        console.print(f"\n[green]Scan Complete: Found {len(found_resources)} interesting file(s)/director(y/ies).[/green]")
        # Optionally, save to a file or further process found_resources
    else:
        console.print(f"\n[yellow]Scan Complete: No interesting files or directories found for {base_url} with the provided wordlist.[/yellow]")

def display_banner(console):
    """Display the ASCII art banner."""
    # Placeholder for ASCII art
    console.print("""
  ██████╗  ███████╗  ██████╗   █████╗   ███╗   ██ ╗██╗  ██╗
  ██╔══██╗ ██╔════╝ ██╔════╝  ██╔═══██╗ ████╗  ██║ ╚██╗██╔╝
  ██████╔╝ █████╗   ██║       ██║   ██║ ██╔██╗ ██║  ╚███╔╝ 
  ██╔══██╗ ██╔══╝   ██║       ██║   ██║ ██║╚██╗██║  ██╔██╗ 
  ██║  ██║ ███████╗ ██╚════╝  ██╚═══██║ ██║ ╚████║ ██╔╝ ██╗
  ╚═╝  ╚═╝ ╚══════╝  ╚██████╝  ╚█████╔╝╚ ═╝  ╚═══╝ ╚═╝  ╚═╝
                    { Made by YA$IN }
    """, style="bold cyan", highlight=False)
    console.print("~ Uncover the shadows of the web with ReconX", style="italic yellow")

def display_menu(console):
    console.print("\n[b]Available Options:[/b]")
    console.print("  1. Whois")
    console.print("  2. DNS")
    console.print("  3. Web Technologies")
    console.print("  4. Subdomain Enumeration (Intelligence - DNS & CT Logs)")
    console.print("  5. Subdomain Enumeration (Wordlist Based)")
    console.print("  6. File & Directory Enumeration")
    console.print("  7. All Lookups (Whois, DNS Info, Web Tech, Subdomain Wordlist)")
    console.print("  8. Exit")

def main():
    """Run the Reconx tool."""
    console = Console()
    display_banner(console)
    
    while True:
        display_menu(console) # Display menu in each loop iteration
        choice = input("Enter your choice (1-8): ")

        if choice == '1':
            domain = input("Enter the domain name for Whois lookup: ")
            get_whois_info(domain, console)
        elif choice == '2':
            domain = input("Enter the domain name for DNS lookup: ")
            get_dns_info(domain, console)
        elif choice == '3':
            domain = input("Enter the domain name for Web Technologies lookup: ")
            get_web_technologies(domain, console)
        elif choice == '4': # Subdomain Enumeration (Intelligence - DNS & CT Logs)
            domain = input("Enter the domain name for Intelligence Subdomain Enumeration: ")
            enumerate_subdomains_intelligence(domain, console)
        elif choice == '5': # Subdomain Enumeration (Wordlist Based) - Moved from choice 4
            domain = input("Enter the domain name for Subdomain Enumeration (Wordlist Based): ")
            mode_choice = input("Choose mode: (1) Lite (built-in list) or (2) Heavy (subdomains.txt): ").strip()
            if mode_choice == '1':
                console.print("[info]Lite mode selected. Using built-in wordlist.[/info]")
                get_subdomains(domain, COMMON_SUBDOMAINS, console)
            elif mode_choice == '2':
                console.print("[info]Heavy mode selected. Attempting to use subdomains.txt...[/info]")
                subdomains_file_path = os.path.join(os.path.dirname(__file__), 'subdomains.txt')
                try:
                    with open(subdomains_file_path, 'r') as f:
                        heavy_wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if heavy_wordlist:
                        get_subdomains(domain, heavy_wordlist, console)
                    else:
                        console.print(f"[warning]subdomains.txt is empty or only contains comments. Falling back to Lite mode.[/warning]")
                        get_subdomains(domain, COMMON_SUBDOMAINS, console)
                except FileNotFoundError:
                    console.print(f"[error]subdomains.txt not found at {subdomains_file_path}. Please create it or choose Lite mode.[/error]")
                    console.print("[info]Falling back to Lite mode.[/info]")
                    get_subdomains(domain, COMMON_SUBDOMAINS, console)
                except Exception as e:
                    console.print(f"[error]Error reading subdomains.txt: {e}. Falling back to Lite mode.[/error]")
                    get_subdomains(domain, COMMON_SUBDOMAINS, console)
            else:
                console.print("[warning]Invalid mode selected. Defaulting to Lite mode.[/warning]")
                get_subdomains(domain, COMMON_SUBDOMAINS, console)
        elif choice == '6': # File & Directory Enumeration
            base_url_input = input("Enter the base URL for File & Directory Enumeration (e.g., http://example.com or https://sub.example.com): ").strip()
            mode_choice = input("Choose mode: (1) Lite (built-in list) or (2) Heavy (paths.txt): ").strip()
            if mode_choice == '1':
                console.print("[info]Lite mode selected. Using built-in path list.[/info]")
                enumerate_files_directories(base_url_input, console, COMMON_PATHS)
            elif mode_choice == '2':
                console.print("[info]Heavy mode selected. Attempting to use paths.txt...[/info]")
                paths_file_path = os.path.join(os.path.dirname(__file__), 'paths.txt')
                try:
                    with open(paths_file_path, 'r') as f:
                        heavy_wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if heavy_wordlist:
                        enumerate_files_directories(base_url_input, console, heavy_wordlist)
                    else:
                        console.print(f"[warning]paths.txt is empty or only contains comments. Falling back to Lite mode.[/warning]")
                        enumerate_files_directories(base_url_input, console, COMMON_PATHS)
                except FileNotFoundError:
                    console.print(f"[error]paths.txt not found at {paths_file_path}. Please create it or choose Lite mode.[/error]")
                    console.print("[info]Falling back to Lite mode.[/info]")
                    enumerate_files_directories(base_url_input, console, COMMON_PATHS)
                except Exception as e:
                    console.print(f"[error]Error reading paths.txt: {e}. Falling back to Lite mode.[/error]")
                    enumerate_files_directories(base_url_input, console, COMMON_PATHS)
            else:
                console.print("[warning]Invalid mode selected. Defaulting to Lite mode.[/warning]")
                enumerate_files_directories(base_url_input, console, COMMON_PATHS)
        elif choice == '7': # All - Wordlist based subdomains for 'All'
            domain_input = input("Enter the domain name for All Lookups (e.g., example.com): ").strip()
            
            # Sanitize domain_input to be a bare domain
            parsed_url = urllib.parse.urlparse(domain_input)
            if parsed_url.netloc: # Handles inputs like http://example.com or example.com:8080
                domain = parsed_url.netloc.split(':')[0] # Remove port if present
            else: # Handles inputs like example.com or example.com/path
                domain = parsed_url.path.split('/')[0] # Take only the part before any path
                domain = domain.split(':')[0] # Remove port if present here too

            if not domain or '.' not in domain: # Basic validation for a domain-like string
                console.print(f"[error]Invalid domain entered: '{domain_input}'. Please provide a valid domain name (e.g., example.com).[/error]")
                continue

            console.print(f"\n[b]--- Starting All Lookups for {domain} ---[/b]")
            get_whois_info(domain, console)
            get_dns_info(domain, console)
            get_web_technologies(domain, console) # Assumes get_web_technologies can form its own URL or tries http/https
            
            console.print(f"\n[b]--- Intelligence Subdomain Enumeration for {domain} ---[/b]")
            live_subdomains_details = enumerate_subdomains_intelligence(domain, console)
            # The enumerate_subdomains_intelligence function already prints its findings if any
            if not live_subdomains_details:
                 console.print(f"[info]No live subdomains found by intelligence scan for {domain}.[/info]")

            # Add File & Directory Enumeration with improved guidance
            console.print(f"\n[b]--- File & Directory Enumeration (as part of All Lookups for {domain}) ---[/b]")
            
            suggestions = []
            if domain: # Ensure domain is not empty before creating suggestions
                suggestions.append(f"https://{domain}")
                suggestions.append(f"http://{domain}")

            if live_subdomains_details:
                console.print("[info]Live subdomains were previously found by the intelligence scan (first few listed below):")
                for i, sub_info in enumerate(live_subdomains_details):
                    if isinstance(sub_info, dict) and 'url' in sub_info and 'status' in sub_info:
                        if i < 3: # Show only first 3 live subdomains here to keep it concise
                            console.print(f"  - {sub_info['url']} (Status: {sub_info['status']})")
                        if len(suggestions) < 5: # Add up to a few live subdomains to suggestions list
                            suggestions.append(sub_info['url'])
                    elif isinstance(sub_info, str):
                        if i < 3:
                            console.print(f"  - {sub_info}")
                        if len(suggestions) < 5:
                             suggestions.append(sub_info)
                console.print("[info]You can use one of these, the original domain (with http/https), or any other URL for File/Dir Enumeration.")
            elif domain:
                console.print(f"[info]No specific live subdomains were automatically detected by the intelligence scan for {domain} earlier.")
                console.print(f"[info]You can try file/directory enumeration on the base domain (e.g., https://{domain} or http://{domain}) or another known URL.")
            else:
                 console.print("[info]Cannot suggest URLs as the initial domain was invalid.")

            prompt_message_parts = []
            unique_suggestions = []
            if suggestions:
                for s in suggestions:
                    if s not in unique_suggestions:
                        unique_suggestions.append(s)
                prompt_message_parts.append(f"e.g., {', '.join(unique_suggestions[:3])}")
            prompt_message_parts.append("or press Enter to skip")
            
            prompt_display = f"Enter the base URL for File & Directory Enumeration ({', '.join(prompt_message_parts)}): "
            if not unique_suggestions:
                prompt_display = f"Enter the base URL for File & Directory Enumeration (e.g., https://yourtarget.com, or press Enter to skip): "

            base_url_input_fd = input(prompt_display).strip()
            
            if base_url_input_fd:
                console.print(f"[info]Using '{base_url_input_fd}' for File & Directory Enumeration with built-in path list (Lite mode).[/info]")
                enumerate_files_directories(base_url_input_fd, console, COMMON_PATHS)
            else:
                console.print(f"[info]Skipping File & Directory Enumeration for this part of 'All Lookups'.[/info]")
            
            console.print(f"\n[b]--- All Lookups for {domain} completed. ---[/b]")
        elif choice == '8': # Exit
            print("Exiting Reconx. Goodbye!")
            break
        else:
            console.print("[bold red]Invalid choice. Please enter a number between 1 and 8.[/bold red]")

def get_whois_info(domain, console):
    """Fetch and display Whois info for a domain."""
    console.print(f"\n[b]--- Whois Information for {domain} (using asyncwhois) ---[/b]")
    try:
        raw_text, parsed_info = asyncwhois.whois(domain, timeout=10)  # Timeout in seconds

        if parsed_info and isinstance(parsed_info, dict):
            table = Table(title=Text(f"Parsed Whois Data for {domain}", style="bold cyan"), show_header=True, header_style="bold magenta")
            table.add_column("Attribute", style="dim cyan", width=30)
            table.add_column("Value", style="green")

            for key, value in parsed_info.items():
                if value:
                    formatted_key = str(key).replace('_', ' ').title()
                    if isinstance(value, list):
                        # Join list items with a newline for display in a single cell
                        value_str = "\n".join(map(str, value))
                    else:
                        value_str = str(value)
                    table.add_row(formatted_key, value_str)
            
            if table.rows:
                console.print(table)
            else:
                console.print("  [yellow]No parsed Whois attributes found to display.[/yellow]")
        
        elif parsed_info: # If parsed_info is not a dict but exists (e.g. a string error message from parser)
             console.print("  [italic yellow]Parsed Whois Output (non-dictionary format):[/italic yellow]")
             console.print(parsed_info)
        else:
            console.print("  [yellow]No parsed Whois information found.[/yellow]")

        if raw_text:
            console.print("\n  [b]--- Raw Whois Output ---[/b]")
            console.print(Text(raw_text, style="grey70")) # Dim color for raw text
        else:
            console.print("  [yellow]No raw Whois output available.[/yellow]")

    except ConnectionResetError:
        console.print(f"\n  [bold red]Connection to the Whois server for {domain} was forcibly closed.[/bold red]")
        console.print("    This can be due to rate limiting, network issues, or server unavailability.")
    except TimeoutError:
        console.print(f"\n  [bold red]Whois lookup for {domain} timed out.[/bold red]")
    except Exception as e:
        console.print(f"\n  [bold red]An error occurred during Whois lookup for {domain}: {type(e).__name__} - {str(e)}[/bold red]")

def get_dns_info(domain, console):
    """Fetch and display DNS info for a domain."""
    console.print(f"\n[b]--- DNS Information for {domain} ---[/b]")
    record_types = [
        'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV',
        'CAA', 'DNSKEY', 'DS', 'DNAME', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'RRSIG'
    ]
    found_any_records_overall = False

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            found_any_records_overall = True
            
            table = Table(title=Text(f"{record_type} Records", style="bold cyan"), show_header=True, header_style="bold magenta")

            if record_type == 'MX':
                table.add_column("Preference", style="dim cyan", width=10)
                table.add_column("Mail Exchange", style="green")
                for rdata in sorted(answers, key=lambda r: r.preference):
                    table.add_row(str(rdata.preference), str(rdata.exchange))
            elif record_type == 'SOA':
                table.add_column("Field", style="dim cyan", width=20)
                table.add_column("Value", style="green")
                for rdata in answers: # Typically only one SOA record
                    table.add_row("MNAME", str(rdata.mname))
                    table.add_row("RNAME", str(rdata.rname))
                    table.add_row("Serial", str(rdata.serial))
                    table.add_row("Refresh", str(rdata.refresh))
                    table.add_row("Retry", str(rdata.retry))
                    table.add_row("Expire", str(rdata.expire))
                    table.add_row("Minimum TTL", str(rdata.minimum))
            elif record_type == 'TXT':
                table.add_column("Text Data", style="green")
                for rdata in answers:
                    full_text = "\n".join(s.decode('utf-8', 'ignore') for s in rdata.strings)
                    table.add_row(full_text)
            elif record_type == 'SRV':
                table.add_column("Priority", style="dim cyan", width=10)
                table.add_column("Weight", style="dim cyan", width=10)
                table.add_column("Port", style="dim cyan", width=10)
                table.add_column("Target", style="green")
                for rdata in sorted(answers, key=lambda r: (r.priority, r.weight)):
                    table.add_row(str(rdata.priority), str(rdata.weight), str(rdata.port), str(rdata.target))
            else: # Default handling for other record types
                table.add_column("Record Data", style="green")
                for rdata in answers:
                    table.add_row(rdata.to_text())
            
            if table.rows:
                console.print(table)
            else:
                 # This case should ideally not be hit if answers were found, but as a fallback:
                console.print(f"  [yellow]No {record_type} records found to display in table for {domain}.[/yellow]")

        except dns.resolver.NoAnswer:
            console.print(f"  [dim]No {record_type} records found for {domain}.[/dim]")
        except dns.resolver.NXDOMAIN:
            console.print(f"  [bold red]Domain {domain} does not exist (NXDOMAIN).[/bold red]")
            return # Stop further DNS lookups if domain doesn't exist
        except dns.resolver.Timeout:
            console.print(f"  [red]DNS query for {record_type} records for {domain} timed out.[/red]")
        except dns.exception.DNSException as e:
            console.print(f"  [red]DNS query for {record_type} failed: {type(e).__name__} - {e}[/red]")
    
    # if not found_any_records_overall and not ???: # This logic is tricky with early exit on NXDOMAIN
        # console.print(f"\n  [yellow]No DNS records of the queried types were found for {domain}.[/yellow]")()

def get_web_technologies(domain, console):
    """Identify web technologies on a domain using Wappalyzer and rich tables."""
    console.print(f"\n[b]--- Web Technologies for {domain} ---[/b]")
    
    if not domain.startswith(('http://', 'https://')):
        url = f"https://{domain}"
    else:
        url = domain

    console.print(f"Analyzing: [link={url}]{url}[/link] (this may take a moment for full scan)...", highlight=False)

    try:
        results = wappalyzer_analyze(url=url, scan_type='full')
        technologies = results.get(url)

        if technologies:
            table = Table(title=Text(f"Detected Technologies on {url}", style="bold cyan"), show_header=True, header_style="bold magenta")
            table.add_column("Technology", style="dim cyan", width=30)
            table.add_column("Version", style="green", width=15)
            table.add_column("Confidence", style="yellow", width=15)
            table.add_column("Categories", style="blue")

            for tech_name, tech_info in technologies.items():
                version = tech_info.get('version', '')
                confidence_val = tech_info.get('confidence')
                confidence = f"{confidence_val}%" if confidence_val is not None else "N/A"
                categories = ", ".join(tech_info.get('categories', []))
                table.add_row(tech_name, version, confidence, categories)
            
            if table.rows:
                console.print(table)
            else:
                console.print(f"  [yellow]No web technologies detected for {url} by Wappalyzer.[/yellow]")
        else:
            console.print(f"  [yellow]No web technologies found or Wappalyzer returned no data for {url}.[/yellow]")
            console.print(f"  [italic]Ensure the domain is correct and accessible.[/italic]")

    except Exception as e:
        console.print(f"\n  [bold red]An error occurred during web technology detection for {url}: {type(e).__name__} - {str(e)}[/bold red]")
        console.print("  [italic yellow]Note: For 'full' Wappalyzer scans, GeckoDriver must be installed and in your system PATH.[/italic yellow]")
        console.print("  [italic yellow]If GeckoDriver is not set up, 'full' scans may fail or provide limited results.[/italic yellow]")
        console.print("  [italic yellow]You can find GeckoDriver releases here: https://github.com/mozilla/geckodriver/releases[/italic yellow]", highlight=False)

def get_subdomains(domain, wordlist_to_use, console):
    """Enumerate subdomains, check liveness, and show HTTP status."""
    console.print(f"\n[b]--- Subdomain Enumeration for {domain} ---[/b]")
    console.print(f"Using a wordlist of {len(wordlist_to_use)} subdomains.")
    
    live_subdomains = []
    protocols = ['https://', 'http://'] # Prefer HTTPS

    with console.status("[yellow]Scanning subdomains...[/yellow]", spinner="dots") as status:
        for word in wordlist_to_use:
            subdomain_base = f"{word}.{domain}".lower()
            status.update(f"[yellow]DNS Check: {subdomain_base}...[/yellow]")
            
            dns_resolved_ips = []
            try:
                answers = dns.resolver.resolve(subdomain_base, 'A')
                dns_resolved_ips = sorted([answer.to_text() for answer in answers])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
                continue # Skip if DNS resolution fails or no A record

            if not dns_resolved_ips:
                continue

            # DNS resolved, now check HTTP/S
            for scheme in protocols:
                url_to_check = f"{scheme}{subdomain_base}"
                status.update(f"[yellow]HTTP Check: {url_to_check}...[/yellow]")
                try:
                    response = requests.get(url_to_check, timeout=5, allow_redirects=False, verify=False, headers={'User-Agent': 'ReconxTool/1.0'})
                    http_status_code = response.status_code
                    responding_scheme = scheme.strip('://')
                    
                    console.print(f"  [green]:heavy_check_mark: Live:[/] [bold cyan]{url_to_check}[/] (IP: {', '.join(dns_resolved_ips)}) -> [yellow]Status: {http_status_code}[/]")
                    
                    live_subdomains.append({'url': url_to_check, 'status': http_status_code, 'scheme': responding_scheme})
                    break # Found a live web server for this base subdomain, no need to check other protocol
                except requests.exceptions.ConnectionError:
                    pass 
                except requests.exceptions.Timeout:
                    console.print(f"  [yellow]TIMEOUT: {url_to_check}[/yellow]")
                except requests.exceptions.RequestException as e:
                    console.print(f"  [yellow]Error checking {url_to_check}: {type(e).__name__} (Could be SSL issue, non-HTTP service, etc.)[/yellow]")
                    pass 
            
    if live_subdomains:
        console.print(f"\n[green]Scan Complete: Found {len(live_subdomains)} live web subdomain(s) for {domain}.[/green]")
        # Display results in a table
        live_subdomains_table = Table(title=Text(f"Live Subdomains for {domain}", style="bold cyan"), show_header=True, header_style="bold magenta")
        live_subdomains_table.add_column("No.", style="dim", width=6)
        live_subdomains_table.add_column("Live Subdomain URL", style="green")
        live_subdomains_table.add_column("Status Code", style="yellow")

        for idx, live_info in enumerate(live_subdomains):
            live_subdomains_table.add_row(str(idx + 1), live_info['url'], str(live_info['status']))
        console.print(live_subdomains_table)
    else:
        console.print(f"\n[yellow]Scan Complete: No live web subdomains found for {domain} using the provided wordlist and HTTP/S check.[/yellow]")
    return live_subdomains

if __name__ == "__main__":
    main()
