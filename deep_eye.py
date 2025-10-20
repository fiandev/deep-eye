#!/usr/bin/env python3
"""
Deep Eye - Advanced AI-Driven Penetration Testing Tool
Main Entry Point
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.config_loader import ConfigLoader
from ai_providers.provider_manager import AIProviderManager

console = Console()
logger = setup_logger()

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ⠀⠀⠀⠀⡀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀              
║  ⠀⢸⠉⣹⠋⠉⢉⡟⢩⢋⠋⣽⡻⠭⢽⢉⠯⠭⠭⠭⢽⡍⢹⡍⠙⣯⠉⠉⠉⠉⠉⣿⢫⠉⠉⠉⢉⡟⠉⢿⢹⠉⢉⣉⢿⡝⡉⢩⢿⣻⢍⠉⠉⠩⢹⣟⡏⠉⠹⡉⢻⡍⡇  
║  ⠀⢸⢠⢹⠀⠀⢸⠁⣼⠀⣼⡝⠀⠀⢸⠘⠀⠀⠀⠀⠈⢿⠀⡟⡄⠹⣣⠀⠀⠐⠀⢸⡘⡄⣤⠀⡼⠁⠀⢺⡘⠉⠀⠀⠀⠫⣪⣌⡌⢳⡻⣦⠀⠀⢃⡽⡼⡀⠀⢣⢸⠸⡇      
║  ⠀⢸⡸⢸⠀⠀⣿⠀⣇⢠⡿⠀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠘⢇⠸⠘⡀⠻⣇⠀⠀⠄⠀⡇⢣⢛⠀⡇⠀⠀⣸⠇⠀⠀⠀⠀⠀⠘⠄⢻⡀⠻⣻⣧⠀⠀⠃⢧⡇⠀⢸⢸⡇⡇  
║  ⠀⢸⡇⢸⣠⠀⣿⢠⣿⡾⠁⠀⢀⡀⠤⢇⣀⣐⣀⠀⠤⢀⠈⠢⡡⡈⢦⡙⣷⡀⠀⠀⢿⠈⢻⣡⠁⠀⢀⠏⠀⠀⠀⢀⠀⠄⣀⣐⣀⣙⠢⡌⣻⣷⡀⢹⢸⡅⠀⢸⠸⡇⡇  
║  ⠀⢸⡇⢸⣟⠀⢿⢸⡿⠀⣀⣶⣷⣾⡿⠿⣿⣿⣿⣿⣿⣶⣬⡀⠐⠰⣄⠙⠪⣻⣦⡀⠘⣧⠀⠙⠄⠀⠀⠀⠀⠀⣨⣴⣾⣿⠿⣿⣿⣿⣿⣿⣶⣯⣿⣼⢼⡇⠀⢸⡇⡇⡇  
║  ⠀⢸⢧⠀⣿⡅⢸⣼⡷⣾⣿⡟⠋⣿⠓⢲⣿⣿⣿⡟⠙⣿⠛⢯⡳⡀⠈⠓⠄⡈⠚⠿⣧⣌⢧⠀⠀⠀⠀⠀⣠⣺⠟⢫⡿⠓⢺⣿⣿⣿⠏⠙⣏⠛⣿⣿⣾⡇⢀⡿⢠⠀⡇  
║  ⠀⢸⢸⠀⢹⣷⡀⢿⡁⠀⠻⣇⠀⣇⠀⠘⣿⣿⡿⠁⠐⣉⡀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠳⠄⠀⠀⠀⠀⠋⠀⠘⡇⠀⠸⣿⣿⠟⠀⢈⣉⢠⡿⠁⣼⠁⣼⠃⣼⠀⡇  
║  ⠀⢸⠸⣀⠈⣯⢳⡘⣇⠀⠀⠈⡂⣜⣆⡀⠀⠀⢀⣀⡴⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⣆⣀⠀⠀⠀⣀⣜⠕⡊⠀⣸⠇⣼⡟⢠⠏⠀⡇  
║  ⠀⢸⠀⡟⠀⢸⡆⢹⡜⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⣾⡏⡇⡎⡇⠀⡇  
║  ⠀⢸⠀⢃⡆⠀⢿⡄⠑⢽⣄⠀⠀⠀⢀⠂⠠⢁⠈⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠄⡐⢀⠂⠀⠀⣠⣮⡟⢹⣯⣸⣱⠁⠀⡇  
║  ⠀⠈⠉⠉⠋⠉⠉⠋⠉⠉⠉⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠋⡟⠉⠉⡿⠋⠋⠋⠉⠉⠁  
║                                                                               
║                  Advanced AI-Driven Penetration Testing Tool                 
║                      Version 1.3.0 - Code Name (Hestia)                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deep Eye - AI-Driven Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python deep_eye.py -u https://example.com
  
  Full scan with AI:
    python deep_eye.py -u https://example.com --ai-provider openai --full-scan
  
  Reconnaissance mode:
    python deep_eye.py -u https://example.com --recon --output recon_report.pdf
        """
    )
    
    # Target options
    parser.add_argument(
        '-u', '--url',
        type=str,
        required=True,
        help='Target URL to scan'
    )
    
    # Scanning options
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=2,
        help='Crawl depth (default: 2)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=5,
        help='Number of threads (default: 5)'
    )
    
    # AI Provider options
    parser.add_argument(
        '--ai-provider',
        type=str,
        choices=['openai', 'claude', 'grok', 'ollama'],
        default='openai',
        help='AI provider to use (default: openai)'
    )
    
    # Scan modes
    parser.add_argument(
        '--recon',
        action='store_true',
        help='Enable reconnaissance mode'
    )
    
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Enable all vulnerability tests'
    )
    
    parser.add_argument(
        '--quick-scan',
        action='store_true',
        help='Quick scan (basic tests only)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output report file path'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['pdf', 'html', 'json'],
        default='html',
        help='Report format (default: html)'
    )
    
    # Network options
    parser.add_argument(
        '--proxy',
        type=str,
        help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '--headers',
        type=str,
        help='Custom headers in JSON format'
    )
    
    parser.add_argument(
        '--cookies',
        type=str,
        help='Cookies in JSON format'
    )
    
    # Advanced options
    parser.add_argument(
        '--config',
        type=str,
        default='config/config.yaml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )
    
    return parser.parse_args()


def display_banner():
    """Display the Deep Eye banner."""
    console.print(BANNER, style="bold cyan")
    console.print("⚠️  [bold yellow]Use only on authorized targets[/bold yellow] ⚠️\n")


def validate_arguments(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        console.print("[bold red]Error:[/bold red] URL must start with http:// or https://")
        return False
    
    # Validate depth
    if args.depth < 1 or args.depth > 10:
        console.print("[bold red]Error:[/bold red] Depth must be between 1 and 10")
        return False
    
    # Validate threads
    if args.threads < 1 or args.threads > 50:
        console.print("[bold red]Error:[/bold red] Threads must be between 1 and 50")
        return False
    
    # Validate headers if provided
    if args.headers:
        try:
            json.loads(args.headers)
        except json.JSONDecodeError:
            console.print("[bold red]Error:[/bold red] Headers must be valid JSON")
            return False
    
    # Validate cookies if provided
    if args.cookies:
        try:
            json.loads(args.cookies)
        except json.JSONDecodeError:
            console.print("[bold red]Error:[/bold red] Cookies must be valid JSON")
            return False
    
    return True


def main():
    """Main execution function."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Display banner
        if not args.no_banner:
            display_banner()
        
        # Validate arguments
        if not validate_arguments(args):
            sys.exit(1)
        
        # Load configuration
        console.print("[bold blue]Loading configuration...[/bold blue]")
        config = ConfigLoader.load(args.config)
        
        # Initialize AI Provider
        console.print(f"[bold blue]Initializing AI Provider: {args.ai_provider}[/bold blue]")
        ai_manager = AIProviderManager(config)
        ai_manager.set_provider(args.ai_provider)
        
        # Parse custom headers and cookies
        custom_headers = json.loads(args.headers) if args.headers else {}
        cookies = json.loads(args.cookies) if args.cookies else {}
        
        # Initialize Scanner Engine
        console.print("[bold blue]Initializing Scanner Engine...[/bold blue]")
        scanner = ScannerEngine(
            target_url=args.url,
            config=config,
            ai_manager=ai_manager,
            depth=args.depth,
            threads=args.threads,
            proxy=args.proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            verbose=args.verbose
        )
        
        # Display scan configuration
        scan_info = Panel(
            f"""[bold]Target:[/bold] {args.url}
[bold]Depth:[/bold] {args.depth}
[bold]Threads:[/bold] {args.threads}
[bold]AI Provider:[/bold] {args.ai_provider}
[bold]Scan Mode:[/bold] {'Full Scan' if args.full_scan else 'Quick Scan' if args.quick_scan else 'Standard Scan'}
[bold]Reconnaissance:[/bold] {'Enabled' if args.recon else 'Disabled'}""",
            title="Scan Configuration",
            border_style="green"
        )
        console.print(scan_info)
        
        # Start scanning
        console.print("\n[bold green]Starting scan...[/bold green]\n")
        
        results = scanner.scan(
            enable_recon=args.recon,
            full_scan=args.full_scan,
            quick_scan=args.quick_scan
        )
        
        # Generate report
        if args.output or results.get('vulnerabilities'):
            console.print("\n[bold blue]Generating report...[/bold blue]")
            report_gen = ReportGenerator(config)
            
            output_path = args.output or f"deep_eye_report_{Path(args.url).stem}.{args.format}"
            report_gen.generate(
                results=results,
                output_path=output_path,
                format=args.format
            )
            
            console.print(f"[bold green]✓[/bold green] Report saved to: {output_path}")
        
        # Display summary
        vuln_count = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        
        summary = Panel(
            f"""[bold]Total Vulnerabilities:[/bold] {vuln_count}
[bold red]Critical:[/bold red] {severity_counts.get('critical', 0)}
[bold yellow]High:[/bold yellow] {severity_counts.get('high', 0)}
[bold blue]Medium:[/bold blue] {severity_counts.get('medium', 0)}
[bold green]Low:[/bold green] {severity_counts.get('low', 0)}
[bold]URLs Crawled:[/bold] {results.get('urls_crawled', 0)}
[bold]Scan Duration:[/bold] {results.get('duration', 'N/A')}""",
            title="Scan Summary",
            border_style="cyan"
        )
        console.print("\n", summary)
        
        console.print("\n[bold green]Scan completed successfully![/bold green] 🎉\n")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
