"""
Local execution mode for the AI agent.
"""
import json
import os
import logging
import tempfile
from typing import List
import git
import glob
import questionary
from agent.services.auditor import SolidityAuditor
from agent.models.solidity_file import SolidityFile
from agent.config import Settings

logger = logging.getLogger(__name__)

def clone_repository(repo_url: str, commit_hash: str | None = None) -> str:
    """
    Clone a GitHub repository to a temporary directory.
    
    Args:
        repo_url: URL of the GitHub repository
        commit_hash: Optional specific commit hash to checkout
        
    Returns:
        Path to the cloned repository
    """
    logger.info(f"Cloning repository: {repo_url}")
    temp_dir = tempfile.mkdtemp()
    repo = git.Repo.clone_from(repo_url, temp_dir)
    
    if commit_hash:
        logger.info(f"Checking out commit: {commit_hash}")
        repo.git.checkout(commit_hash)
        
    return temp_dir

def select_files_interactively(all_files: List[str]) -> List[str]:
    """
    Display all .sol files and let the user select which ones to audit using questionary.
    
    Args:
        all_files: List of all Solidity file paths found
        
    Returns:
        List of selected file paths
    """
    if not all_files:
        logger.warning("No Solidity files found in repository")
        return []
    
    logger.info(f"Found {len(all_files)} Solidity files. Displaying selection interface.")
    try:
        print("\nPlease select the files to audit:")
        choices = []
        for file_path in all_files:
            # Show a cleaned path for better UX
            choices.append({"name": file_path, "value": file_path})
            
        # Use questionary's checkbox component for multi-selection
        selected_files = questionary.checkbox(
            "Select Solidity files to audit:",
            choices=choices,
        ).ask()
        
        if not selected_files:
            logger.warning("No files selected")
            return []
        
        logger.info(f"Selected {len(selected_files)} files for audit")
        return selected_files
    except Exception as e:
        logger.error(f"Error during file selection: {str(e)}")
        logger.info("Falling back to processing all files")
        return all_files

def find_solidity_contracts(repo_path: str, only_selected: bool = False) -> List[SolidityFile]:
    """
    Find all Solidity contracts in a repository.
    
    Args:
        repo_path: Path to the repository
        only_selected: Whether to enable interactive file selection
        
    Returns:
        List of SolidityFile objects
    """
    logger.info(f"Searching for Solidity contracts in {repo_path}")
    
    # Find all .sol files
    all_files = [
        os.path.relpath(f, repo_path)
        for f in glob.glob(f"{repo_path}/**/*.sol", recursive=True)
    ]
    
    if only_selected:
        selected_files = select_files_interactively(all_files)
    else:
        selected_files = all_files
    
    solidity_files = []
    for file_path in selected_files:
        try:
            abs_path = os.path.join(repo_path, file_path)
            with open(abs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            solidity_files.append(
                SolidityFile(
                    path=file_path,
                    content=content
                )
            )
        except Exception as e:
            logger.error(f"Error reading contract {file_path}: {str(e)}")
    
    return solidity_files

def save_audit_results(output_path: str, audit: str):
    """
    Save audit results to a file.
    
    Args:
        output_path: Path to save the results to
        audit: Audit results
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(audit)
        logger.info(f"Security audit results saved to {output_path}")
    except Exception as e:
        logger.error(f"Error saving audit results: {str(e)}")
        raise

def process_local(repo_url: str, output_path: str, config: Settings, commit_hash: str | None = None, only_selected: bool = False):
    """
    Process a repository in local mode.
    
    Args:
        repo_url: URL of the GitHub repository
        output_path: Path to save the audit results
        config: Application configuration
        commit_hash: Optional specific commit hash to checkout
        only_selected: Whether to enable interactive file selection
    """
    # Configure logging to both console and file
    log_file = config.log_file
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Clone the repository
        repo_path = clone_repository(repo_url, commit_hash)
        
        # Find Solidity contracts
        solidity_contracts = find_solidity_contracts(repo_path, only_selected)
        
        if not solidity_contracts:
            logger.warning(f"No Solidity contracts found in repository {repo_url}")
            return
        
        logger.info(f"Found {len(solidity_contracts)} Solidity contracts to audit")
        
        # Audit contracts
        auditor = SolidityAuditor(config.openai_api_key, config.openai_model)
        audit = auditor.audit_files(solidity_contracts)
        audit_dict = [finding.model_dump() for finding in audit.findings]

        # Save results
        save_audit_results(output_path, json.dumps(audit_dict, indent=2))
        
        logger.info("Security audit completed successfully")
        
    except Exception as e:
        logger.error(f"Error in local processing: {str(e)}")
        raise