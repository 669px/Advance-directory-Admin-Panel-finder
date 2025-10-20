import requests
import os
import logging
import webbrowser
import time
import json
import csv
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from tqdm import tqdm
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, DownloadColumn
from rich.table import Table
from rich.live import Live
from rich.prompt import Prompt
from rich.panel import Panel
from rich.syntax import Syntax
from rich.layout import Layout
from rich.traceback import install as install_rich_traceback
from rich.align import Align

install_rich_traceback()

class AdvancedScanner:
    def __init__(self, base_url, wordlist_path, threads=10, user_agent="Mozilla/5.0", 
                 timeout=5, auto_browse=False, browse_delay=2, verify_ssl=True, 
                 follow_redirects=True, rate_limit=0, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.user_agent = user_agent
        self.timeout = timeout
        self.auto_browse = auto_browse
        self.browse_delay = browse_delay
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.rate_limit = rate_limit
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.console = Console()
        
        self.results = {
            'found': [],
            'redirects': [],
            'admin_panels': [],
            'interesting': [],
            'backup_files': [],
            'errors': [],
            'response_time_distribution': defaultdict(int)
        }
        
        self.live_table = Table(title="🔍 Live Scan Results", show_header=True, header_style="bold cyan")
        self.live_table.add_column("Status", style="cyan", width=8)
        self.live_table.add_column("Path", style="magenta", width=40)
        self.live_table.add_column("Code", justify="right", width=6)
        self.live_table.add_column("Time", justify="right", width=8)
        self.live_table.add_column("Type", style="yellow", width=12)
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        if self.proxy:
            self.session.proxies.update(self.proxy)
        
        self.scan_start_time = None
        self.total_requests = 0
        self.live_results = []
        

        self.admin_keywords = ['admin', 'login', 'dashboard', 'panel', 'management', 
                               'control', 'cpanel', 'user area', 'staff', 'backend']
        self.backup_keywords = ['.bak', '.backup', '.old', '.sql', '.zip', '.tar', 
                               '.gz', '.rar', '~', '.swp', '.swo']
        self.interesting_keywords = ['config', 'secret', 'key', 'password', 'token', 
                                     'credential', 'api_key', 'private']

    def load_wordlist(self):
        """Load and validate wordlist with duplicate detection"""
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as file:
                words = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
            
            original_count = len(words)
            words = list(set(words))   
            
            self.console.print(f"[cyan]✓ Loaded {len(words)} unique paths (removed {original_count - len(words)} duplicates)[/cyan]")
            return words
        except FileNotFoundError:
            self.console.print(f"[red]✗ Wordlist file not found: {self.wordlist_path}[/red]")
            return []
        except Exception as e:
            self.console.print(f"[red]✗ Error loading wordlist: {e}[/red]")
            return []

    def validate_url(self):
        """Validate if the base URL is accessible"""
        try:
            response = self.session.head(self.base_url, timeout=self.timeout, verify=self.verify_ssl)
            self.console.print(f"[green]✓ Target URL is accessible (Status: {response.status_code})[/green]")
            return True
        except Exception as e:
            self.console.print(f"[red]✗ Cannot reach target URL: {e}[/red]")
            return False

    def validate_proxy(self):
        """Validate if proxy is working"""
        if not self.proxy:
            return True
        
        try:
            self.console.print("[cyan]Testing proxy connection...[/cyan]")
            response = self.session.head("http://httpbin.org/ip", timeout=self.timeout, verify=self.verify_ssl)
            if response.status_code == 200:
                self.console.print("[green]✓ Proxy is working correctly[/green]")
                return True
        except requests.exceptions.ProxyError:
            self.console.print("[red]✗ Proxy connection failed: Invalid proxy or unreachable[/red]")
            return False
        except requests.exceptions.Timeout:
            self.console.print("[red]✗ Proxy connection timed out[/red]")
            return False
        except Exception as e:
            self.console.print(f"[red]✗ Proxy validation error: {e}[/red]")
            return False

    def categorize_response_time(self, response_time):
        """Categorize response time for analysis"""
        if response_time < 0.1:
            return "Very Fast"
        elif response_time < 0.5:
            return "Fast"
        elif response_time < 1:
            return "Normal"
        elif response_time < 2:
            return "Slow"
        else:
            return "Very Slow"

    def detect_framework(self, headers, content):
        """Detect web framework/server technology"""
        frameworks = []
        
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            frameworks.append('Apache')
        if 'nginx' in server:
            frameworks.append('Nginx')
        if 'iis' in server or 'microsoft' in server:
            frameworks.append('IIS')
        if 'php' in server or 'php' in content.lower():
            frameworks.append('PHP')
        
        if 'x-powered-by' in headers:
            frameworks.append(headers['x-powered-by'])
        
        return frameworks

    def scan_path(self, path):
        """Scan a single path with detailed analysis"""
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)
        
        try:
            url = urljoin(self.base_url, path)
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, 
                                       allow_redirects=self.follow_redirects)
            
            response_time = response.elapsed.total_seconds()
            response_category = self.categorize_response_time(response_time)
            self.results['response_time_distribution'][response_category] += 1
            
            result = {
                'path': path,
                'url': url,
                'status': response.status_code,
                'content_length': len(response.content),
                'response_time': response_time,
                'response_time_category': response_category,
                'headers': dict(response.headers),
                'frameworks': self.detect_framework(dict(response.headers), response.text[:1000]),
                'timestamp': datetime.now().isoformat()
            }
            

            if response.status_code == 200:
                result['found'] = True
                self.results['found'].append(result)
                

                live_entry = {
                    'status': '✓',
                    'path': path[:40],
                    'code': response.status_code,
                    'time': f"{response_time:.2f}s",
                    'type': 'Found'
                }
                self.live_results.append(live_entry)
                
                if self.auto_browse:
                    time.sleep(self.browse_delay)
                    webbrowser.open(url)
                return result
            

            elif response.status_code in [301, 302, 303, 307, 308]:
                result['redirect_to'] = response.headers.get('Location', 'Unknown')
                self.results['redirects'].append(result)
                
                live_entry = {
                    'status': '→',
                    'path': path[:40],
                    'code': response.status_code,
                    'time': f"{response_time:.2f}s",
                    'type': 'Redirect'
                }
                self.live_results.append(live_entry)
                return result
            

            elif response.status_code in [201, 204, 206]:
                self.results['found'].append(result)
                
                live_entry = {
                    'status': '~',
                    'path': path[:40],
                    'code': response.status_code,
                    'time': f"{response_time:.2f}s",
                    'type': 'Success'
                }
                self.live_results.append(live_entry)
                return result
            

            elif response.status_code == 403:
                self.results['interesting'].append(result)
                
                live_entry = {
                    'status': '!',
                    'path': path[:40],
                    'code': response.status_code,
                    'time': f"{response_time:.2f}s",
                    'type': 'Forbidden'
                }
                self.live_results.append(live_entry)
                return result
            
            return None
                
        except requests.Timeout:
            self.results['errors'].append({'path': path, 'error': 'Timeout', 'timestamp': datetime.now().isoformat()})
            return None
        except requests.RequestException as e:
            self.results['errors'].append({'path': path, 'error': str(e), 'timestamp': datetime.now().isoformat()})
            return None

    def scan_admin_panels(self, path):
        """Enhanced admin panel detection"""
        try:
            url = urljoin(self.base_url, path)
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            response_text = response.text.lower()
            
            matching_keywords = [kw for kw in self.admin_keywords if kw in response_text]
            
            if response.status_code == 200 and matching_keywords:
                result = {
                    'path': path,
                    'url': url,
                    'status': response.status_code,
                    'keywords_found': matching_keywords,
                    'content_length': len(response.content),
                    'frameworks': self.detect_framework(dict(response.headers), response.text[:1000]),
                    'timestamp': datetime.now().isoformat()
                }
                self.results['admin_panels'].append(result)
                
                live_entry = {
                    'status': '★',
                    'path': path[:40],
                    'code': response.status_code,
                    'time': '-',
                    'type': 'Admin Panel'
                }
                self.live_results.append(live_entry)
                
                if self.auto_browse:
                    time.sleep(self.browse_delay)
                    webbrowser.open(url)
                return result
            return None
                
        except requests.RequestException:
            return None

    def update_live_display(self, total_scanned, total_paths):
        """Create live display table"""
        table = Table(title="🔍 Live Scan Results", show_header=True, header_style="bold cyan", border_style="cyan")
        table.add_column("Status", style="cyan", width=8)
        table.add_column("Path", style="magenta", width=40)
        table.add_column("Code", justify="right", width=6)
        table.add_column("Time", justify="right", width=8)
        table.add_column("Type", style="yellow", width=12)
        

        for entry in self.live_results[-15:]:
            status_style = "green" if entry['status'] == "✓" else "yellow" if entry['status'] in ["→", "!"] else "cyan" if entry['status'] == "★" else "white"
            table.add_row(
                f"[{status_style}]{entry['status']}[/{status_style}]",
                entry['path'],
                str(entry['code']),
                entry['time'],
                entry['type']
            )
        

        summary_text = f"[cyan]Scanned: {total_scanned}/{total_paths} | Found: {len(self.results['found'])} | Admin: {len(self.results['admin_panels'])} | Errors: {len(self.results['errors'])}[/cyan]"
        
        return table, summary_text

    def save_scan_results(self, format='json'):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"scan_results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
        
        elif format == 'csv':
            filename = f"scan_results_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Path', 'URL', 'Status Code', 'Response Time', 'Content Length', 'Timestamp'])
                
                for item in self.results['found']:
                    writer.writerow(['Found', item['path'], item['url'], item['status'], 
                                   f"{item['response_time']:.2f}s", item['content_length'], item['timestamp']])
                for item in self.results['admin_panels']:
                    writer.writerow(['Admin Panel', item['path'], item['url'], item['status'], 'N/A', item['content_length'], item['timestamp']])
                for item in self.results['redirects']:
                    writer.writerow(['Redirect', item['path'], item['url'], item['status'], 'N/A', 'N/A', item['timestamp']])
        
        elif format == 'html':
            filename = f"scan_results_{timestamp}.html"
            html = self._generate_html_report()
            with open(filename, 'w') as f:
                f.write(html)
        
        elif format == 'txt':
            filename = f"scan_results_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("HAIDER TOOLS - SCAN RESULTS\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Target: {self.base_url}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("FOUND PATHS:\n")
                f.write("-" * 80 + "\n")
                for item in self.results['found']:
                    f.write(f"{item['path']} ({item['status']}) - {item['response_time']:.2f}s\n")
                
                f.write("\n\nADMIN PANELS:\n")
                f.write("-" * 80 + "\n")
                for item in self.results['admin_panels']:
                    f.write(f"{item['path']} - Keywords: {', '.join(item['keywords_found'])}\n")
                
                f.write("\n\nREDIRECTS:\n")
                f.write("-" * 80 + "\n")
                for item in self.results['redirects']:
                    f.write(f"{item['path']} -> {item.get('redirect_to', 'Unknown')}\n")
        
        return filename

    def _generate_html_report(self):
        """Generate detailed HTML report with clickable links"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_date_short = datetime.now().strftime("%Y%m%d_%H%M%S")
        

        total_found = len(self.results['found'])
        total_admin = len(self.results['admin_panels'])
        total_redirects = len(self.results['redirects'])
        total_errors = len(self.results['errors'])
        
        found_rows = ''.join(f"""
            <tr>
                <td><a href="{r['url']}" target="_blank" style="color: #3498db; text-decoration: none; font-weight: bold;">{r['path']}</a></td>
                <td><span class="status-badge status-{r['status']}">{r['status']}</span></td>
                <td>{r['response_time']:.2f}s</td>
                <td>{r['content_length']} bytes</td>
                <td><button class="copy-btn" onclick="copyToClipboard('{r['url']}')">📋</button></td>
            </tr>
        """ for r in self.results['found'])
        
        admin_rows = ''.join(f"""
            <tr>
                <td><a href="{r['url']}" target="_blank" style="color: #3498db; text-decoration: none; font-weight: bold;">{r['path']}</a></td>
                <td><span class="keywords">{', '.join(r['keywords_found'])}</span></td>
                <td><span class="status-badge status-{r['status']}">{r['status']}</span></td>
                <td><button class="copy-btn" onclick="copyToClipboard('{r['url']}')">📋</button></td>
            </tr>
        """ for r in self.results['admin_panels'])
        
        redirect_rows = ''.join(f"""
            <tr>
                <td><a href="{r['url']}" target="_blank" style="color: #3498db; text-decoration: none; font-weight: bold;">{r['path']}</a></td>
                <td><a href="{r.get('redirect_to', '#')}" target="_blank" style="color: #f39c12; text-decoration: none;">{r.get('redirect_to', 'Unknown')}</a></td>
                <td><span class="status-badge status-{r['status']}">{r['status']}</span></td>
                <td><button class="copy-btn" onclick="copyToClipboard('{r['url']}')">📋</button></td>
            </tr>
        """ for r in self.results['redirects'])
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Haider Tools - Scan Report</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }}
                
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                
                .header {{
                    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                    color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                    margin-bottom: 30px;
                    text-align: center;
                }}
                
                .header h1 {{
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                }}
                
                .header p {{
                    font-size: 1.1em;
                    opacity: 0.9;
                    margin: 5px 0;
                }}
                
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                
                .card {{
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    text-align: center;
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }}
                
                .card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 15px 30px rgba(0,0,0,0.2);
                }}
                
                .card h3 {{
                    color: #2c3e50;
                    margin-bottom: 10px;
                    font-size: 1.1em;
                }}
                
                .card .number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #667eea;
                    text-shadow: 1px 1px 2px rgba(0,0,0,0.05);
                }}
                
                .section {{
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }}
                
                .section h2 {{
                    color: #2c3e50;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 3px solid #667eea;
                    font-size: 1.8em;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}
                
                th {{
                    background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
                    color: white;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    border: none;
                }}
                
                td {{
                    padding: 12px 15px;
                    border-bottom: 1px solid #ecf0f1;
                    word-break: break-word;
                }}
                
                tr:hover {{
                    background-color: #f8f9fa;
                    transition: background-color 0.2s ease;
                }}
                
                tr:last-child td {{
                    border-bottom: none;
                }}
                
                a {{
                    color: #667eea;
                    text-decoration: none;
                    font-weight: 600;
                    transition: color 0.2s ease;
                }}
                
                a:hover {{
                    color: #764ba2;
                    text-decoration: underline;
                }}
                
                .status-badge {{
                    display: inline-block;
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-weight: 600;
                    font-size: 0.9em;
                }}
                
                .status-200 {{
                    background-color: #d4edda;
                    color: #155724;
                }}
                
                .status-301, .status-302, .status-303, .status-307, .status-308 {{
                    background-color: #fff3cd;
                    color: #856404;
                }}
                
                .status-403 {{
                    background-color: #f8d7da;
                    color: #721c24;
                }}
                
                .status-404 {{
                    background-color: #e2e3e5;
                    color: #383d41;
                }}
                
                .copy-btn {{
                    background-color: #667eea;
                    color: white;
                    border: none;
                    padding: 6px 10px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 0.9em;
                    transition: background-color 0.2s ease;
                }}
                
                .copy-btn:hover {{
                    background-color: #764ba2;
                }}
                
                .keywords {{
                    background-color: #e8f4f8;
                    color: #0c5460;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.9em;
                }}
                
                .footer {{
                    text-align: center;
                    color: white;
                    margin-top: 40px;
                    padding: 20px;
                    font-size: 0.95em;
                }}
                
                .empty-state {{
                    text-align: center;
                    padding: 40px;
                    color: #7f8c8d;
                    font-size: 1.1em;
                }}
                
                .filter-btn {{
                    background-color: #667eea;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    margin: 10px 5px;
                    font-size: 1em;
                    transition: background-color 0.2s ease;
                }}
                
                .filter-btn:hover {{
                    background-color: #764ba2;
                }}
                
                .filter-btn.active {{
                    background-color: #764ba2;
                }}
                
                @media print {{
                    body {{
                        background: white;
                    }}
                    .copy-btn, .filter-btn {{
                        display: none;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Haider Tools - Scan Report</h1>
                    <p><strong>Target:</strong> {self.base_url}</p>
                    <p><strong>Scan Date:</strong> {timestamp}</p>
                    <p><strong>Report ID:</strong> {scan_date_short}</p>
                </div>
                
                <div class="summary">
                    <div class="card">
                        <h3>✓ Found Paths</h3>
                        <div class="number">{total_found}</div>
                    </div>
                    <div class="card">
                        <h3>★ Admin Panels</h3>
                        <div class="number">{total_admin}</div>
                    </div>
                    <div class="card">
                        <h3>→ Redirects</h3>
                        <div class="number">{total_redirects}</div>
                    </div>
                    <div class="card">
                        <h3>✗ Errors</h3>
                        <div class="number">{total_errors}</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>📁 Found Paths & Directories</h2>
                    {"<table>" + """
                        <thead>
                            <tr>
                                <th style="width: 40%;">Path / URL</th>
                                <th style="width: 10%;">Status</th>
                                <th style="width: 15%;">Response Time</th>
                                <th style="width: 20%;">Content Length</th>
                                <th style="width: 10%;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                    """ + (found_rows if found_rows else '<tr><td colspan="5" class="empty-state">No paths found</td></tr>') + """
                        </tbody>
                    </table>""" if total_found > 0 else '<div class="empty-state">No paths found during scan</div>'}
                </div>
                
                <div class="section">
                    <h2>★ Admin Panels Detected</h2>
                    {"<table>" + """
                        <thead>
                            <tr>
                                <th style="width: 35%;">Path / URL</th>
                                <th style="width: 25%;">Keywords Found</th>
                                <th style="width: 15%;">Status</th>
                                <th style="width: 10%;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                    """ + (admin_rows if admin_rows else '<tr><td colspan="4" class="empty-state">No admin panels detected</td></tr>') + """
                        </tbody>
                    </table>""" if total_admin > 0 else '<div class="empty-state">No admin panels detected during scan</div>'}
                </div>
                
                <div class="section">
                    <h2>→ Redirects</h2>
                    {"<table>" + """
                        <thead>
                            <tr>
                                <th style="width: 30%;">Original Path</th>
                                <th style="width: 40%;">Redirects To</th>
                                <th style="width: 15%;">Status</th>
                                <th style="width: 10%;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                    """ + (redirect_rows if redirect_rows else '<tr><td colspan="4" class="empty-state">No redirects found</td></tr>') + """
                        </tbody>
                    </table>""" if total_redirects > 0 else '<div class="empty-state">No redirects detected during scan</div>'}
                </div>
                
                <div class="footer">
                    <p>Generated by Haider Tools | Advanced Web Scanner</p>
                    <p>All links are clickable and can be opened directly in your browser</p>
                </div>
            </div>
            
            <script>
                function copyToClipboard(text) {{
                    navigator.clipboard.writeText(text).then(() => {{
                        alert('URL copied to clipboard: ' + text);
                    }}).catch(() => {{
                        alert('Failed to copy URL');
                    }});
                }}
                
                function printReport() {{
                    window.print();
                }}
            </script>
        </body>
        </html>
        """
        return html

    def display_summary(self):
        """Display comprehensive scan summary"""

        table = Table(title="📊 Scan Summary", show_header=True, header_style="bold cyan", border_style="cyan")
        table.add_column("Category", style="cyan", width=20)
        table.add_column("Count", style="magenta", justify="right", width=10)
        
        table.add_row("✓ Found Paths", str(len(self.results['found'])))
        table.add_row("★ Admin Panels", str(len(self.results['admin_panels'])))
        table.add_row("→ Redirects", str(len(self.results['redirects'])))
        table.add_row("⚠ Interesting", str(len(self.results['interesting'])))
        table.add_row("✗ Errors", str(len(self.results['errors'])))
        
        self.console.print(table)

    def run(self, scan_type='full', check_backups=False):
        """Main scan execution with live display"""
        self.scan_start_time = time.time()
        
        wordlist = self.load_wordlist()
        if not wordlist:
            self.console.print("[red]No valid paths to scan. Exiting.[/red]")
            return


        if self.proxy:
            if not self.validate_proxy():
                console_continue = Prompt.ask("[yellow]Proxy validation failed. Continue without proxy?[/yellow]", choices=["y", "n"])
                if console_continue.lower() != 'y':
                    return
                self.proxy = None
                self.session.proxies.clear()


        if not self.validate_url():
            return

        self.console.print(f"\n[bold cyan]Starting scan on: {self.base_url}[/bold cyan]")
        if self.proxy:
            self.console.print(f"[cyan]Using proxy: {self.proxy.split('@')[-1] if '@' in str(self.proxy) else self.proxy}[/cyan]\n")
        else:
            self.console.print("[cyan]Proxy: None\n[/cyan]")
        
        total_scanned = 0
        
        if scan_type in ['full', 'directories']:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_path, path): path for path in wordlist}
                
                with Live(self.console.print("Initializing..."), refresh_per_second=2) as live:
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            total_scanned += 1
                            
                            if total_scanned % 5 == 0:   
                                table, summary = self.update_live_display(total_scanned, len(wordlist))
                                display = f"{table}\n{summary}"
                                live.update(display)
                        except Exception as e:
                            total_scanned += 1
        
        if scan_type in ['full', 'admin']:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_admin_panels, path): path for path in wordlist}
                
                with Live(self.console.print("Scanning Admin Panels..."), refresh_per_second=2) as live:
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            total_scanned += 1
                            
                            if total_scanned % 5 == 0:
                                table, summary = self.update_live_display(total_scanned, len(wordlist) * 2)
                                display = f"{table}\n{summary}"
                                live.update(display)
                        except Exception:
                            total_scanned += 1
        

        self.console.print("\n")
        self.display_summary()
        
        scan_duration = time.time() - self.scan_start_time
        self.console.print(f"[green]✓ Scan completed in {scan_duration:.2f} seconds[/green]\n")

def load_config(file_path="config.json"):
    """Load configuration from file"""
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)
    return {}

def save_config(config, file_path="config.json"):
    """Save configuration to file"""
    with open(file_path, 'w') as file:
        json.dump(config, file, indent=4)

def main():
    console = Console()
    console.print(Panel.fit("[bold cyan]🔍 Haider Tools - Advanced Web Scanner[/bold cyan]", border_style="cyan"))
    
    config = load_config()
    

    auto_detected_wordlist = None
    if os.path.exists("wordlist.txt"):
        auto_detected_wordlist = "wordlist.txt"
        console.print("[green]✓ Auto-detected wordlist.txt in current directory[/green]")
    

    base_url = console.input("[cyan]Enter base URL[/cyan] (or press Enter to use saved): ").strip() or config.get("base_url", "")
    if not base_url:
        console.print("[red]✗ Base URL is required![/red]")
        return
    

    if auto_detected_wordlist:
        use_auto = console.input("[cyan]Use auto-detected wordlist.txt? (y/n)[/cyan] (default y): ").lower() != 'n'
        wordlist_path = auto_detected_wordlist if use_auto else (console.input("[cyan]Enter wordlist path[/cyan]: ").strip() or config.get("wordlist_path", ""))
    else:
        wordlist_path = console.input("[cyan]Enter wordlist path[/cyan] (or press Enter to use saved): ").strip() or config.get("wordlist_path", "")
    
    if not wordlist_path:
        console.print("[red]✗ Wordlist path is required![/red]")
        return
    
    threads = int(console.input("[cyan]Threads[/cyan] (default 10): ").strip() or config.get("threads", 10))
    user_agent = console.input("[cyan]User-Agent[/cyan] (press Enter for default): ").strip() or config.get("user_agent", "Mozilla/5.0")
    timeout = int(console.input("[cyan]Timeout (seconds)[/cyan] (default 5): ").strip() or config.get("timeout", 5))
    rate_limit = float(console.input("[cyan]Rate limit (seconds between requests, 0 for none)[/cyan] (default 0): ").strip() or "0")
    
    auto_browse = console.input("[cyan]Auto-open URLs? (y/n)[/cyan] (default n): ").lower() == 'y'
    browse_delay = int(console.input("[cyan]Browse delay (seconds)[/cyan] (default 2): ").strip() or 2) if auto_browse else 0
    verify_ssl = console.input("[cyan]Verify SSL? (y/n)[/cyan] (default y): ").lower() != 'n'
    

    use_proxy = console.input("[cyan]Use proxy? (y/n)[/cyan] (default n): ").lower() == 'y'
    proxy = None
    proxy_type = None
    
    if use_proxy:
        console.print("[yellow]Proxy Configuration Options:[/yellow]")
        console.print("  1. HTTP Proxy (http://ip:port)")
        console.print("  2. HTTPS Proxy (https://ip:port)")
        console.print("  3. SOCKS5 Proxy (socks5://ip:port)")
        console.print("  4. SOCKS4 Proxy (socks4://ip:port)")
        
        proxy_type = console.input("[cyan]Select proxy type (1-4) or paste custom proxy URL[/cyan]: ").strip()
        
        if proxy_type in ['1', '2', '3', '4']:
            proxy_url = console.input("[cyan]Enter proxy server address (ip:port)[/cyan]: ").strip()
            if proxy_url:
                if proxy_type == '1':
                    proxy = f"http://{proxy_url}"
                    console.print(f"[green]✓ HTTP Proxy configured: {proxy}[/green]")
                elif proxy_type == '2':
                    proxy = f"https://{proxy_url}"
                    console.print(f"[green]✓ HTTPS Proxy configured: {proxy}[/green]")
                elif proxy_type == '3':
                    proxy = f"socks5://{proxy_url}"
                    console.print(f"[green]✓ SOCKS5 Proxy configured: {proxy}[/green]")
                elif proxy_type == '4':
                    proxy = f"socks4://{proxy_url}"
                    console.print(f"[green]✓ SOCKS4 Proxy configured: {proxy}[/green]")
        else:
            proxy = proxy_type if proxy_type.startswith(('http://', 'https://', 'socks4://', 'socks5://')) else None
            if proxy:
                console.print(f"[green]✓ Custom proxy configured: {proxy}[/green]")
            else:
                console.print("[yellow]! Invalid proxy format, proceeding without proxy[/yellow]")
                proxy = None
        

        if proxy:
            auth_needed = console.input("[cyan]Does proxy require authentication? (y/n)[/cyan] (default n): ").lower() == 'y'
            if auth_needed:
                username = console.input("[cyan]Enter proxy username[/cyan]: ").strip()
                password = console.input("[cyan]Enter proxy password[/cyan]: ").strip()
                if username and password:
                    if "://" in proxy:
                        scheme, rest = proxy.split("://", 1)
                        proxy = f"{scheme}://{username}:{password}@{rest}"
                        console.print("[green]✓ Proxy authentication credentials added[/green]")
    else:
        console.print("[cyan]Proceeding without proxy[/cyan]")
    
    scan_type = console.input("[cyan]Scan type? (full/directories/admin)[/cyan] (default full): ").lower().strip() or "full"
    check_backups = console.input("[cyan]Check for backup files? (y/n)[/cyan] (default n): ").lower() == 'y'
    

    save_on_exit = console.input("[cyan]Auto-save results when scan completes? (y/n)[/cyan] (default y): ").lower() != 'n'
    export_format = console.input("[cyan]Export format? (json/csv/html/txt)[/cyan] (default json): ").lower().strip() or "json" if save_on_exit else None
    
    config.update({
        "base_url": base_url,
        "wordlist_path": wordlist_path,
        "threads": threads,
        "user_agent": user_agent,
        "timeout": timeout,
        "rate_limit": rate_limit,
        "auto_browse": auto_browse,
        "browse_delay": browse_delay,
        "verify_ssl": verify_ssl
    })
    save_config(config)
    
    logging.basicConfig(
        filename="haider_tools.log",
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    scanner = AdvancedScanner(base_url, wordlist_path, threads, user_agent, timeout, 
                             auto_browse, browse_delay, verify_ssl, rate_limit=rate_limit, proxy=proxy)
    
    try:
        scanner.run(scan_type, check_backups)
        

        if save_on_exit and export_format:
            console.print("\n[cyan]Saving scan results...[/cyan]")
            filename = scanner.save_scan_results(export_format)
            console.print(f"[green]✓ Results saved to {filename}[/green]")
        else:

            want_save = console.input("\n[cyan]Save results to file? (y/n)[/cyan]: ").lower() == 'y'
            if want_save:
                formats = console.input("[cyan]Export format? (json/csv/html/txt)[/cyan] (default json): ").lower().strip() or "json"
                filename = scanner.save_scan_results(formats)
                console.print(f"[green]✓ Results saved to {filename}[/green]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]! Scan interrupted by user[/yellow]")
        

        want_save = console.input("[cyan]Save partial results before exit? (y/n)[/cyan]: ").lower() == 'y'
        if want_save:
            formats = console.input("[cyan]Export format? (json/csv/html/txt)[/cyan] (default json): ").lower().strip() or "json"
            filename = scanner.save_scan_results(formats)
            console.print(f"[green]✓ Partial results saved to {filename}[/green]")

if __name__ == "__main__":
    main()
