"""
Main entry point for the Solidity audit agent.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import List, Optional

from agent.config import Settings
from agent.services.auditor import SolidityAuditor
from agent.models.solidity_file import SolidityFile
from agent.services.report_generator import ReportGenerator
from agent.server import start_server

logger = logging.getLogger(__name__)


def setup_logging(log_level: str, log_file: Optional[str] = None):
    """
    Set up logging configuration.
    
    Args:
        log_level: Logging level
        log_file: Path to log file
    """
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers
    )


def get_solidity_files(repo_path: str) -> List[SolidityFile]:
    """
    Get all Solidity files from a repository.
    
    Args:
        repo_path: Path to repository
        
    Returns:
        List of SolidityFile objects
    """
    solidity_files = []
    
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.sol'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                solidity_files.append(
                    SolidityFile(
                        path=file_path,
                        content=content
                    )
                )
    
    return solidity_files


def clone_repository(repo_url: str, target_dir: str) -> str:
    """
    Clone a Git repository.
    
    Args:
        repo_url: URL of the repository
        target_dir: Directory to clone into
        
    Returns:
        Path to cloned repository
    """
    import tempfile
    import subprocess
    
    if not target_dir:
        target_dir = tempfile.mkdtemp()
    
    try:
        subprocess.run(['git', 'clone', repo_url, target_dir], check=True)
        logger.info(f"Cloned repository {repo_url} to {target_dir}")
        return target_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {str(e)}")
        sys.exit(1)


def local_audit(args, config: Settings):
    """
    Run a local audit.
    
    Args:
        args: Command line arguments
        config: Application configuration
    """
    # Clone repository if URL provided
    repo_path = args.repo
    if repo_path.startswith('http'):
        repo_path = clone_repository(repo_path, args.target_dir)
    
    # Get Solidity files
    solidity_files = get_solidity_files(repo_path)
    
    if not solidity_files:
        logger.error(f"No Solidity files found in {repo_path}")
        sys.exit(1)
    
    logger.info(f"Found {len(solidity_files)} Solidity files")
    
    # Create auditor
    auditor = SolidityAuditor(
        api_key=config.openai_api_key,
        model=config.openai_model,
        api_base_url=config.api_base_url
    )
    
    # Run audit
    audit_result = auditor.audit_files(solidity_files)
    
    # Generate report in requested format
    report_generator = ReportGenerator()
    
    if args.format == 'text':
        report = audit_result
    elif args.format == 'json':
        report = report_generator.generate_json_report(audit_result)
    elif args.format == 'sarif':
        report = report_generator.generate_sarif_report(audit_result)
    elif args.format == 'html':
        html_path = args.output.replace('.txt', '.html')
        report_generator.generate_html_report(audit_result, html_path)
        report = f"HTML report generated at {html_path}"
    else:
        report = audit_result
    
    # Write report to file or stdout
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info(f"Audit report written to {args.output}")
    else:
        print(report)


def server_mode(args, config: Settings):
    """
    Run in server mode.
    
    Args:
        args: Command line arguments
        config: Application configuration
    """
    start_server(args.host, args.port, config)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Solidity Audit Agent')
    subparsers = parser.add_subparsers(dest='mode', help='Mode of operation')
    
    # Local mode
    local_parser = subparsers.add_parser('local', help='Run a local audit')
    local_parser.add_argument('--repo', required=True, help='Path or URL to repository')
    local_parser.add_argument('--target-dir', help='Directory to clone repository into')
    local_parser.add_argument('--output', help='Path to output file')
    local_parser.add_argument('--format', choices=['text', 'json', 'sarif', 'html'], default='text',
                             help='Output format')
    
    # Server mode
    server_parser = subparsers.add_parser('server', help='Run in server mode')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    
    args = parser.parse_args()
    
    # Load configuration
    config = Settings()
    
    # Set up logging
    setup_logging(config.log_level, config.log_file)
    
    # Run in selected mode
    if args.mode == 'local':
        local_audit(args, config)
    elif args.mode == 'server':
        server_mode(args, config)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()