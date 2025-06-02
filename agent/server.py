"""
Server implementation for the AI agent.
"""
import json
import logging
import httpx
import tempfile
import os
import zipfile
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel
from agent.types import TaskResponse
from agent.services.auditor import Audit, SolidityAuditor
from agent.config import Settings
from typing import Optional

logger = logging.getLogger(__name__)
app = FastAPI(title="Solidity Audit Agent")

class Notification(BaseModel):
    """Payload received from Agent4rena webhook."""
    task_id: str
    task_repository_url: str  # URL to download repository ZIP
    task_details_url: str     # URL to get task details with selected files
    post_findings_url: str

class TaskContent(BaseModel):
    """Model for task smart contract content."""
    task_id: str
    files_content: str

async def fetch_solidity_files(contracts_url: str, config: Settings) -> str:
    """
    Fetch Solidity files from the API.
    
    Args:
        contracts_url: URL to fetch contracts from
        task_id: Task ID
        file_paths: List of file paths to fetch
        
    Returns:
        List of SolidityFile objects
    """
    try:
        async with httpx.AsyncClient() as client:
            # Fetch all contracts at once from the contracts_url
            response = await client.get(
                contracts_url,
                headers={"X-API-Key": config.agentarena_api_key}
            )
            response.raise_for_status()
            
            # Parse the response
            return response.json()
        
    except Exception as e:
        logger.error(f"Error fetching contracts: {str(e)}")
    
    return None

async def send_audit_results(callback_url: str, task_id: str, audit: Audit):
    """
    Send audit results back to the API.
    
    Args:
        callback_url: URL to send results to
        task_id: Task ID
        audit: Audit results
    """
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            # Convert Pydantic models to dict first
            findings_dict = [finding.model_dump() for finding in audit.findings]
            payload = {"task_id": task_id, "findings": findings_dict}
            
            # Log detailed payload information for debugging
            logger.info(f"Sending audit results to {callback_url} for task {task_id}")
            logger.debug(f"Request payload: {json.dumps(payload, indent=2)}")
            
            # Add more debugging info and increase timeout
            response = await client.post(
                callback_url, 
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": app.state.config.agentarena_api_key
                }
            )
            # Log response details
            logger.info(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {response.headers}")
            logger.debug(f"Response content: {response.text}")
            
            response.raise_for_status()
            logger.info(f"Successfully sent audit results for task {task_id}")
            
    except httpx.RequestError as e:
        # Network-related errors
        logger.error(f"Network error when sending audit results: {str(e)}", exc_info=True)
    except httpx.HTTPStatusError as e:
        # Server returned error status
        logger.error(f"HTTP error {e.response.status_code} when sending audit results: {e.response.text}", exc_info=True)
    except Exception as e:
        # Any other unexpected errors
        logger.error(f"Unexpected error sending audit results: {str(e)}", exc_info=True)

async def fetch_task_details(details_url: str, config: Settings) -> TaskResponse:
    """
    Fetch task details including the list of selected files.
    
    Args:
        details_url: URL to fetch task details
        config: Application configuration
        
    Returns:
        TaskResponse object containing task details including selectedFiles
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                details_url,
                headers={"X-API-Key": config.agentarena_api_key}
            )
            response.raise_for_status()
            task_data = response.json()
            return TaskResponse(**task_data)
    except Exception as e:
        logger.error(f"Error fetching task details: {str(e)}", exc_info=True)
        return None

async def download_repository(repo_url: str, config: Settings) -> str:
    """
    Download repository ZIP file and extract to a temporary directory.
    
    Args:
        repo_url: URL to download repository ZIP
        config: Application configuration
        
    Returns:
        Path to the extracted repository directory
    """
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "repo.zip")
        
        # Download the ZIP file
        async with httpx.AsyncClient() as client:
            response = await client.get(
                repo_url,
                headers={"X-API-Key": config.agentarena_api_key}
            )
            response.raise_for_status()
            
            # Save ZIP file
            with open(zip_path, "wb") as f:
                f.write(response.content)
            
            # Extract ZIP file
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find the actual repository root directory
            # Most repositories have a single root directory inside the ZIP
            contents = os.listdir(extract_dir)
            if len(contents) == 1 and os.path.isdir(os.path.join(extract_dir, contents[0])):
                # If there's only one item and it's a directory, that's our repo root
                repo_root = os.path.join(extract_dir, contents[0])
                logger.info(f"Found repository root directory: {contents[0]}")
                return repo_root
            else:
                # If there are multiple items, use the extract_dir as the root
                logger.info("Using extracted directory as repository root")
                return extract_dir
    except Exception as e:
        logger.error(f"Error downloading repository: {str(e)}", exc_info=True)
        return None

def read_and_concatenate_files(repo_dir: str, selected_files: list) -> str:
    """
    Read and concatenate content of selected files from the repository.
    
    Args:
        repo_dir: Path to the repository directory
        selected_files: List of file paths to read
        
    Returns:
        String with all files concatenated with headers
    """
    concatenated = ""
    
    try:
        for file_path in selected_files:
            full_path = os.path.join(repo_dir, file_path)
            print(f"Reading file: {full_path}")
            if os.path.isfile(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                        concatenated += f"// {file_path}\n{file_content}\n\n"
                except UnicodeDecodeError:
                    # Try with different encoding if utf-8 fails
                    with open(full_path, 'r', encoding='latin-1') as f:
                        file_content = f.read()
                        concatenated += f"// {file_path}\n{file_content}\n\n"
            else:
                logger.warning(f"Selected file not found: {file_path}")
        
        return concatenated
    except Exception as e:
        logger.error(f"Error reading and concatenating files: {str(e)}", exc_info=True)
        return ""

async def process_notification(notification: Notification, config: Settings):
    """
    Process a notification by fetching files, auditing them, and sending results.
    
    Args:
        notification: Notification payload
        config: Application configuration
    """
    try:
        logger.info(f"Processing notification for task {notification.task_id}")
        logger.info(f"Notification: {notification}")
        
        # Fetch task details to get selected files
        task_details = await fetch_task_details(notification.task_details_url, config)
        if not task_details:
            logger.error(f"Failed to get task details for task {notification.task_id}")
            return

        selected_files = task_details.selectedFiles or []
        if not selected_files:
            logger.warning(f"No files selected for task {notification.task_id}")
            return
            
        # Download and extract repository
        repo_dir = await download_repository(notification.task_repository_url, config)
        if not repo_dir:
            logger.error(f"Failed to download repository for task {notification.task_id}")
            return
        
        # Store repository path for future use
        repo_storage_path = os.path.join(config.data_dir, f"repo_{notification.task_id}")
        if not os.path.exists(config.data_dir):
            os.makedirs(config.data_dir, exist_ok=True)
            
        # If the repository already exists for this task, remove it and update
        if os.path.exists(repo_storage_path):
            import shutil
            shutil.rmtree(repo_storage_path)

        # Copy the extracted repository to a persistent location
        import shutil
        shutil.copytree(repo_dir, repo_storage_path)
        logger.info(f"Repository for task {notification.task_id} stored at {repo_storage_path}")
        
        # Read and concatenate selected files
        concatenated_contracts = read_and_concatenate_files(repo_storage_path, selected_files)
        if not concatenated_contracts:
            logger.warning(f"No valid contracts content found for task {notification.task_id}")
            return
        
        # Read and concatenate selected docs
        selected_docs = task_details.selectedDocs or []
        concatenated_docs = read_and_concatenate_files(repo_storage_path, selected_docs)
        if not concatenated_docs:
            logger.info(f"No valid docs content found for task {notification.task_id}")
            # Continue anyway as docs are
        
        # Audit files
        auditor = SolidityAuditor(config.openai_api_key, config.openai_model)
        audit = auditor.audit_files(concatenated_contracts, concatenated_docs, task_details.additionalLinks, task_details.additionalDocs, task_details.qaResponses)
        
        # Send results back
        await send_audit_results(notification.post_findings_url, notification.task_id, audit)
        
        # Clean up only the temporary directory, but keep the repository copy
        if os.path.exists(os.path.dirname(repo_dir)):
            shutil.rmtree(os.path.dirname(repo_dir))
            logger.info(f"Temporary directory cleaned up while preserving repository at {repo_storage_path}")
        
    except Exception as e:
        logger.error(f"Error processing notification: {str(e)}", exc_info=True)

@app.post("/webhook")
async def webhook(
    notification: Notification, 
    background_tasks: BackgroundTasks,
    authorization: str = Header(None)
):
    """
    Webhook endpoint for receiving notifications.
    
    Args:
        notification: Notification payload
        background_tasks: FastAPI background tasks
        authorization: Authorization header for webhook validation
        
    Returns:
        Acknowledgement response
    """
    # Validate authorization token
    expected_auth = f"token {app.state.config.webhook_auth_token}"
    if not authorization or authorization != expected_auth:
        logger.warning(f"Invalid authorization token provided")
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    logger.info(f"Received notification for task {notification.task_id}")
    
    # Process the notification in the background
    background_tasks.add_task(
        process_notification, 
        notification=notification, 
        config=app.state.config
    )
    
    return {"status": "processing", "task_id": notification.task_id}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

def start_server(host: str, port: int, config: Settings):
    """
    Start the FastAPI server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        config: Application configuration
    """
    import uvicorn
    
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
    
    # Store config in app state
    app.state.config = config
    
    # Start the server
    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port) 