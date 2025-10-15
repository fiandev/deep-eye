"""
Report Generator
Creates professional security assessment reports
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template
from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generate professional security reports."""
    
    def __init__(self, config: Dict):
        """Initialize report generator."""
        self.config = config
        self.report_config = config.get('reporting', {})
        self.template_dir = Path(__file__).parent.parent.parent / 'templates'
    
    def generate(self, results: Dict, output_path: str, format: str = 'html'):
        """
        Generate security report.
        
        Args:
            results: Scan results
            output_path: Output file path
            format: Report format (html, pdf, json)
        """
        if format == 'json':
            self._generate_json(results, output_path)
        elif format == 'html':
            self._generate_html(results, output_path)
        elif format == 'pdf':
            self._generate_pdf(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, results: Dict, output_path: str):
        """Generate JSON report."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"JSON report generated: {output_path}")
    
    def _generate_html(self, results: Dict, output_path: str):
        """Generate HTML report."""
        template_content = self._get_html_template()
        template = Template(template_content)
        
        # Prepare data for template
        report_data = {
            'title': 'Deep Eye Security Assessment Report',
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': results.get('target'),
            'scan_duration': results.get('duration'),
            'summary': self._generate_summary(results),
            'vulnerabilities': self._sort_vulnerabilities(results.get('vulnerabilities', [])),
            'severity_counts': results.get('severity_summary', {}),
            'urls_scanned': results.get('urls_crawled', 0),
            'reconnaissance': results.get('reconnaissance', {}),
        }
        
        html_content = template.render(**report_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
    
    def _generate_pdf(self, results: Dict, output_path: str):
        """Generate PDF report."""
        # First generate HTML
        html_path = output_path.replace('.pdf', '.html')
        self._generate_html(results, html_path)
        
        # Convert HTML to PDF (using weasyprint)
        try:
            from weasyprint import HTML
            HTML(html_path).write_pdf(output_path)
            logger.info(f"PDF report generated: {output_path}")
            
            # Clean up temporary HTML
            Path(html_path).unlink()
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            logger.info(f"HTML report available at: {html_path}")
    
    def _generate_summary(self, results: Dict) -> str:
        """Generate executive summary."""
        total_vulns = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        
        summary = f"""
        This security assessment identified {total_vulns} potential security issues on the target system.
        
        Critical vulnerabilities require immediate attention as they pose significant risk to the organization.
        High and medium severity issues should be addressed in order of priority.
        
        Risk Distribution:
        - Critical: {severity_counts.get('critical', 0)} issues
        - High: {severity_counts.get('high', 0)} issues
        - Medium: {severity_counts.get('medium', 0)} issues
        - Low: {severity_counts.get('low', 0)} issues
        """
        
        return summary.strip()
    
    def _sort_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Sort vulnerabilities by severity."""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        return sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
    
    def _get_html_template(self) -> str:
        """Get HTML report template."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
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
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metadata-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .metadata-card h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .severity-card {
            padding: 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .severity-critical { background-color: #8B0000; }
        .severity-high { background-color: #FF4500; }
        .severity-medium { background-color: #FFA500; }
        .severity-low { background-color: #FFD700; color: #333; }
        .severity-info { background-color: #87CEEB; color: #333; }
        
        .severity-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .vulnerability {
            border-left: 4px solid #ddd;
            padding: 20px;
            margin-bottom: 20px;
            background: #f9f9f9;
            border-radius: 4px;
        }
        
        .vulnerability.critical { border-left-color: #8B0000; }
        .vulnerability.high { border-left-color: #FF4500; }
        .vulnerability.medium { border-left-color: #FFA500; }
        .vulnerability.low { border-left-color: #FFD700; }
        
        .vulnerability h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .vulnerability-meta {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            flex-wrap: wrap;
        }
        
        .vulnerability-meta span {
            background: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        
        .code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {{ title }}</h1>
            <p>Generated: {{ generated_date }}</p>
        </div>
        
        <div class="metadata">
            <div class="metadata-card">
                <h3>Target</h3>
                <p>{{ target }}</p>
            </div>
            <div class="metadata-card">
                <h3>Scan Duration</h3>
                <p>{{ scan_duration }}</p>
            </div>
            <div class="metadata-card">
                <h3>URLs Scanned</h3>
                <p>{{ urls_scanned }}</p>
            </div>
        </div>
        
        <div class="severity-grid">
            <div class="severity-card severity-critical">
                <h3>{{ severity_counts.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="severity-card severity-high">
                <h3>{{ severity_counts.high }}</h3>
                <p>High</p>
            </div>
            <div class="severity-card severity-medium">
                <h3>{{ severity_counts.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="severity-card severity-low">
                <h3>{{ severity_counts.low }}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{{ summary }}</p>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities</h2>
            {% if vulnerabilities %}
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity }}">
                    <h3>{{ vuln.type }}</h3>
                    <div class="vulnerability-meta">
                        <span><strong>Severity:</strong> {{ vuln.severity|upper }}</span>
                        <span><strong>URL:</strong> {{ vuln.url }}</span>
                        {% if vuln.parameter %}
                        <span><strong>Parameter:</strong> {{ vuln.parameter }}</span>
                        {% endif %}
                    </div>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% if vuln.payload %}
                    <p><strong>Payload:</strong></p>
                    <div class="code">{{ vuln.payload }}</div>
                    {% endif %}
                    <p><strong>Evidence:</strong> {{ vuln.evidence }}</p>
                    <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
                </div>
                {% endfor %}
            {% else %}
                <p>No vulnerabilities detected.</p>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>This report was generated by Deep Eye - Advanced AI-Driven Penetration Testing Tool</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
'''
