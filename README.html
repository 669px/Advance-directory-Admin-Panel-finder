<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Haider Tools - Advanced Web Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 20px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        header p {
            font-size: 1.2em;
            opacity: 0.95;
            margin-bottom: 20px;
        }

        .badges {
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 20px;
        }

        .badge {
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            border: 1px solid rgba(255,255,255,0.3);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        section {
            background: white;
            margin: 30px 0;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }

        section h2 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
        }

        section h3 {
            color: #764ba2;
            font-size: 1.4em;
            margin: 25px 0 15px 0;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }

        .feature-card {
            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            transition: transform 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-5px);
        }

        .feature-card h4 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }

        .feature-card p {
            color: #555;
            line-height: 1.6;
        }

        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            line-height: 1.5;
        }

        .code-block code {
            display: block;
        }

        .command {
            display: inline-block;
            background: #f0f0f0;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #667eea;
            font-weight: 600;
        }

        .table-wrapper {
            overflow-x: auto;
            margin: 25px 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
        }

        tr:hover {
            background-color: #f8f9fa;
        }

        .highlight {
            background: #fffacd;
            padding: 2px 6px;
            border-radius: 3px;
        }

        .success {
            color: #27ae60;
            font-weight: 600;
        }

        .warning {
            color: #e74c3c;
            font-weight: 600;
        }

        .info-box {
            background: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }

        .info-box strong {
            color: #0c5460;
        }

        .warning-box {
            background: #fff5e6;
            border-left: 4px solid #f39c12;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }

        .warning-box strong {
            color: #856404;
        }

        .do-dont {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin: 30px 0;
        }

        .do-box {
            background: #d4edda;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #27ae60;
        }

        .dont-box {
            background: #f8d7da;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }

        .do-box h4, .dont-box h4 {
            margin-bottom: 15px;
            font-size: 1.1em;
        }

        .do-box ul, .dont-box ul {
            list-style: none;
            padding-left: 0;
        }

        .do-box li, .dont-box li {
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }

        .do-box li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #27ae60;
            font-weight: bold;
        }

        .dont-box li:before {
            content: "✗";
            position: absolute;
            left: 0;
            color: #e74c3c;
            font-weight: bold;
        }

        .step-list {
            list-style: none;
            padding: 0;
            counter-reset: step-counter;
        }

        .step-list li {
            counter-increment: step-counter;
            padding: 15px 0 15px 50px;
            position: relative;
            margin-bottom: 10px;
        }

        .step-list li:before {
            content: counter(step-counter);
            position: absolute;
            left: 0;
            top: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.1em;
        }

        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 600;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1em;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }

        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 40px 20px;
            margin-top: 60px;
        }

        footer p {
            margin: 10px 0;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-card .label {
            font-size: 0.95em;
            opacity: 0.9;
        }

        @media (max-width: 768px) {
            header h1 {
                font-size: 2em;
            }

            .do-dont {
                grid-template-columns: 1fr;
            }

            .features-grid {
                grid-template-columns: 1fr;
            }

            section {
                padding: 25px;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>Haider Tools</h1>
        <p>Advanced Web Scanner & Directory Enumeration</p>
        <div class="badges">
            <span class="badge">Python 3.7+</span>
            <span class="badge">MIT License</span>
            <span class="badge">Active Development</span>
            <span class="badge">Enterprise Ready</span>
        </div>
    </header>

    <div class="container">
        <!-- Overview -->
        <section>
            <h2>Overview</h2>
            <p>Haider Tools is a professional-grade web reconnaissance platform designed for authorized security assessments. It combines multi-threaded scanning, intelligent detection algorithms, and enterprise-grade reporting into a powerful command-line tool.</p>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="number">10+</div>
                    <div class="label">Advanced Features</div>
                </div>
                <div class="stat-card">
                    <div class="number">4</div>
                    <div class="label">Export Formats</div>
                </div>
                <div class="stat-card">
                    <div class="number">1000s</div>
                    <div class="label">Paths/Minute</div>
                </div>
                <div class="stat-card">
                    <div class="number">100%</div>
                    <div class="label">Configurable</div>
                </div>
            </div>
        </section>

        <!-- Key Features -->
        <section>
            <h2>Key Capabilities</h2>
            <div class="features-grid">
                <div class="feature-card">
                    <h4>⚡ Multi-threaded Scanning</h4>
                    <p>Concurrent path enumeration with configurable worker threads for maximum efficiency.</p>
                </div>
                <div class="feature-card">
                    <h4>🎯 Admin Panel Detection</h4>
                    <p>ML-style keyword matching to identify administrative interfaces and control panels.</p>
                </div>
                <div class="feature-card">
                    <h4>📊 Response Analysis</h4>
                    <p>Real-time categorization of response times and pattern recognition.</p>
                </div>
                <div class="feature-card">
                    <h4>🔍 Framework Detection</h4>
                    <p>Automatic identification of web servers, CMS platforms, and technologies.</p>
                </div>
                <div class="feature-card">
                    <h4>🌐 Proxy Support</h4>
                    <p>HTTP, HTTPS, SOCKS4, SOCKS5 with authentication for distributed scanning.</p>
                </div>
                <div class="feature-card">
                    <h4>🛡️ SSL Control</h4>
                    <p>Flexible certificate verification for testing environments and production systems.</p>
                </div>
                <div class="feature-card">
                    <h4>⏱️ Rate Limiting</h4>
                    <p>Configurable request throttling for stealth operations and target protection.</p>
                </div>
                <div class="feature-card">
                    <h4>🎨 Live Reporting</h4>
                    <p>Real-time dashboard with rich terminal formatting and progress tracking.</p>
                </div>
                <div class="feature-card">
                    <h4>📁 Multi-format Export</h4>
                    <p>JSON, CSV, HTML, and TXT outputs for various use cases and integrations.</p>
                </div>
                <div class="feature-card">
                    <h4>💾 Config Persistence</h4>
                    <p>Automatic saving of scan profiles for quick reuse and consistency.</p>
                </div>
            </div>
        </section>

        <!-- Installation -->
        <section>
            <h2>Quick Start</h2>
            
            <h3>Prerequisites</h3>
            <ul class="step-list">
                <li><strong>Python 3.7</strong> or higher</li>
                <li><strong>~50MB</strong> disk space for dependencies</li>
                <li><strong>Internet connection</strong> for HTTP requests</li>
            </ul>

            <h3>Installation Steps</h3>
            <ol class="step-list">
                <li>
                    <strong>Clone the repository</strong>
                    <div class="code-block">
                        <code>git clone https://github.com/yourusername/haider-tools.git
cd haider-tools</code>
                    </div>
                </li>
                <li>
                    <strong>Install dependencies</strong>
                    <div class="code-block">
                        <code>pip install -r requirements.txt</code>
                    </div>
                </li>
                <li>
                    <strong>Run the scanner</strong>
                    <div class="code-block">
                        <code>python haider_tools.py</code>
                    </div>
                </li>
            </ol>

            <div class="info-box">
                <strong>Tip:</strong> The tool will guide you through configuration with an interactive prompt on first run. Settings are saved to <span class="command">config.json</span> for future scans.
            </div>
        </section>

        <!-- Usage Examples -->
        <section>
            <h2>Usage Examples</h2>

            <h3>Basic Directory Enumeration</h3>
            <div class="code-block">
                <code>python haider_tools.py
# Enter target: https://example.com
# Enter wordlist: wordlist.txt
# Select scan type: full
# Export format: html</code>
            </div>

            <h3>Stealth Scanning with Proxy</h3>
            <div class="code-block">
                <code>python haider_tools.py
# Threads: 5 (recommended for stealth)
# Rate limit: 0.5 (half-second between requests)
# Use proxy: yes
# Proxy: socks5://proxy.server:1080</code>
            </div>

            <h3>Admin Panel Discovery</h3>
            <div class="code-block">
                <code>python haider_tools.py
# Target: https://app.com
# Scan type: admin
# Export format: html</code>
            </div>
        </section>

        <!-- Wordlist Format -->
        <section>
            <h2>Wordlist Format</h2>
            <p>Simple text file with one path per line:</p>
            <div class="code-block">
                <code>admin
administrator
login
dashboard
api/v1/users
api/v2/admin
.env
config.php
backup.sql
test.php

# Comments start with #
# Add as many paths as needed</code>
            </div>

            <h3>Popular Wordlist Sources</h3>
            <ul style="margin: 20px 0 20px 30px;">
                <li><strong>SecLists</strong> - https://github.com/danielmiessler/SecLists</li>
                <li><strong>Web Discovery</strong> - SecLists/Discovery/Web-Content</li>
                <li><strong>Custom Wordlists</strong> - Tailored to your target application</li>
            </ul>
        </section>

        <!-- Configuration -->
        <section>
            <h2>Configuration</h2>
            
            <h3>Saved Configuration (config.json)</h3>
            <div class="code-block">
                <code>{
    "base_url": "https://example.com",
    "wordlist_path": "wordlist.txt",
    "threads": 10,
    "timeout": 5,
    "rate_limit": 0,
    "verify_ssl": true,
    "user_agent": "Mozilla/5.0"
}</code>
            </div>

            <h3>Configuration Options</h3>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Option</th>
                            <th>Description</th>
                            <th>Default</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="command">threads</span></td>
                            <td>Number of concurrent workers</td>
                            <td>10</td>
                        </tr>
                        <tr>
                            <td><span class="command">timeout</span></td>
                            <td>Request timeout in seconds</td>
                            <td>5</td>
                        </tr>
                        <tr>
                            <td><span class="command">rate_limit</span></td>
                            <td>Delay between requests (seconds)</td>
                            <td>0</td>
                        </tr>
                        <tr>
                            <td><span class="command">verify_ssl</span></td>
                            <td>Verify SSL certificates</td>
                            <td>true</td>
                        </tr>
                        <tr>
                            <td><span class="command">auto_browse</span></td>
                            <td>Auto-open discovered URLs</td>
                            <td>false</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Proxy Configuration -->
        <section>
            <h2>Proxy Configuration</h2>

            <h3>Supported Proxy Types</h3>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Format</th>
                            <th>Example</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>HTTP Proxy</td>
                            <td><span class="command">http://ip:port</span></td>
                            <td>http://proxy.server:8080</td>
                        </tr>
                        <tr>
                            <td>HTTPS Proxy</td>
                            <td><span class="command">https://ip:port</span></td>
                            <td>https://proxy.server:8080</td>
                        </tr>
                        <tr>
                            <td>SOCKS4</td>
                            <td><span class="command">socks4://ip:port</span></td>
                            <td>socks4://proxy.server:1080</td>
                        </tr>
                        <tr>
                            <td>SOCKS5</td>
                            <td><span class="command">socks5://ip:port</span></td>
                            <td>socks5://proxy.server:1080</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <h3>With Authentication</h3>
            <div class="code-block">
                <code>socks5://username:password@proxy.server:1080
http://user:pass@proxy.server:8080</code>
            </div>

            <div class="info-box">
                <strong>Note:</strong> The tool automatically validates proxy connectivity before starting the scan.
            </div>
        </section>

        <!-- Output Formats -->
        <section>
            <h2>Output Formats</h2>

            <h3>HTML Report</h3>
            <p>Beautiful interactive dashboard with:</p>
            <ul style="margin: 15px 0 15px 30px;">
                <li>Summary statistics cards</li>
                <li>Clickable links to discovered URLs</li>
                <li>Response time analysis</li>
                <li>Framework detection results</li>
                <li>Print-friendly layout</li>
            </ul>

            <h3>JSON Export</h3>
            <p>Complete structured data including all request/response details, headers, metadata, and timestamps.</p>

            <h3>CSV Export</h3>
            <p>Spreadsheet-compatible format for data analysis, trend identification, and integration with other tools.</p>

            <h3>TXT Report</h3>
            <p>Human-readable format with organized sections for found paths, admin panels, redirects, and errors.</p>
        </section>

        <!-- Performance Tuning -->
        <section>
            <h2>Performance Tuning</h2>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Parameter</th>
                            <th>Aggressive</th>
                            <th>Balanced</th>
                            <th>Stealth</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Threads</strong></td>
                            <td>50</td>
                            <td>10</td>
                            <td>5</td>
                        </tr>
                        <tr>
                            <td><strong>Timeout</strong></td>
                            <td>3s</td>
                            <td>5s</td>
                            <td>10s</td>
                        </tr>
                        <tr>
                            <td><strong>Rate Limit</strong></td>
                            <td>0</td>
                            <td>0</td>
                            <td>0.5s</td>
                        </tr>
                        <tr>
                            <td><strong>Use Case</strong></td>
                            <td>Lab Testing</td>
                            <td>General Purpose</td>
                            <td>Production</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Results Interpretation -->
        <section>
            <h2>Results Interpretation</h2>

            <h3>HTTP Status Codes</h3>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Code</th>
                            <th>Meaning</th>
                            <th>Significance</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="highlight">200</span></td>
                            <td>OK - Successfully accessible</td>
                            <td style="color: #27ae60; font-weight: 600;">Valid Path Found</td>
                        </tr>
                        <tr>
                            <td><span class="highlight">301/302/307/308</span></td>
                            <td>Redirect</td>
                            <td>Path exists but redirects</td>
                        </tr>
                        <tr>
                            <td><span class="highlight">403</span></td>
                            <td>Forbidden</td>
                            <td>Path exists, access denied</td>
                        </tr>
                        <tr>
                            <td><span class="highlight">404</span></td>
                            <td>Not Found</td>
                            <td>Path does not exist</td>
                        </tr>
                        <tr>
                            <td><span class="highlight">500+</span></td>
                            <td>Server Error</td>
                            <td>Server issue or misconfiguration</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <h3>Response Time Categories</h3>
            <ul style="margin: 20px 0 20px 30px;">
                <li><strong>Very Fast:</strong> &lt; 100ms (likely static content/cached)</li>
                <li><strong>Fast:</strong> 100-500ms (typical response)</li>
                <li><strong>Normal:</strong> 500ms-1s (database queries)</li>
                <li><strong>Slow:</strong> 1-2s (complex operations)</li>
                <li><strong>Very Slow:</strong> &gt; 2s (potential bottleneck)</li>
            </ul>
        </section>

        <!-- Best Practices -->
        <section>
            <h2>Best Practices</h2>

            <div class="do-dont">
                <div class="do-box">
                    <h4>Do:</h4>
                    <ul>
                        <li>Get written authorization before scanning</li>
                        <li>Use rate limiting for production systems</li>
                        <li>Test on your own infrastructure first</li>
                        <li>Review logs after each scan</li>
                        <li>Save results for comparison over time</li>
                        <li>Use appropriate thread counts</li>
                    </ul>
                </div>
                <div class="dont-box">
                    <h4>Don't:</h4>
                    <ul>
                        <li>Scan without authorization</li>
                        <li>Use excessive thread counts</li>
                        <li>Bypass SSL verification on production</li>
                        <li>Leave default configurations</li>
                        <li>Ignore rate limiting indicators</li>
                        <li>Share raw scan results publicly</li>
                    </ul>
                </div>
            </div>
        </section>

        <!-- Legal Notice -->
        <section>
            <h2>Legal Notice</h2>
            <div class="warning-box">
                <strong>Important:</strong> Haider Tools is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Users must:
                <ul style="margin: 15px 0 15px 30px;">
                    <li>Obtain written permission before scanning any system</li>
                    <li>Comply with local laws and regulations</li>
                    <li>Use only for authorized security assessments</li>
                    <li>Assume full responsibility for tool misuse</li>
                </ul>
                The authors accept no liability for unauthorized use or system damage.
            </div>
        </section>

        <!-- Requirements -->
        <section>
            <h2>Requirements</h2>
            <div class="code-block">
                <code>requests==2.31.0       # HTTP client
urllib3==2.1.0         # URL utilities & proxy
tqdm==4.66.1          # Progress tracking
rich==13.7.0          # Terminal formatting</code>
            </div>
            <p style="margin-top: 15px;">All dependencies are lightweight and actively maintained.</p>
        </section>

        <!-- Support -->
        <section>
            <h2>Support & Contributing</h2>
            <p>Found a bug? Have a feature request?</p>
            <ul style="margin: 15px 0 15px 30px;">
                <li>Open an issue on GitHub</li>
                <li>Check existing documentation</li>
                <li>Review activity logs for debugging</li>
                <li>Submit pull requests for improvements</li>
            </ul>
        </section>
    </div>

    <footer>
        <p><strong>Haider Tools</strong> - Advanced Web Scanner</p>
        <p>Professional reconnaissance. Enterprise results.</p>
        <p style="margin-top: 20px; opacity: 0.8;">© 2024 | MIT License | Active Development</p>
    </footer>
</body>
</html>
