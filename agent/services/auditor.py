"""
Core service for auditing Solidity contracts using OpenAI.
"""
import json
import logging
from typing import List
from pydantic import BaseModel, Field
from openai import OpenAI

from agent.services.prompts.audit_prompt import AUDIT_PROMPT

logger = logging.getLogger(__name__)

class VulnerabilityFinding(BaseModel):
    """Model representing a single vulnerability finding."""
    title: str = Field(..., description="Title of the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: str = Field(..., description="Severity level: Critical, High, Medium, Low, or Informational")
    file_paths: List[str] = Field(..., description="List of file paths containing the vulnerability")

class Audit(BaseModel):
    """Model representing the complete audit response."""
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="List of vulnerability findings")

class SolidityAuditor:
    """Service for auditing Solidity contracts using OpenAI."""
    
    def __init__(self, api_key: str, model: str):
        """
        Initialize the auditor with OpenAI credentials.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
        """
        self.model = model
        self.client = OpenAI(api_key=api_key)

    def audit_files(self, contracts: str, docs: str = "", additional_links: List[str] = None, additional_docs: str = None, qa_responses: List = None) -> Audit:
        """
        Audit Solidity contracts and return structured findings.
        
        Args:
            contracts: String containing all contract code
            docs: String containing documentation
            additional_links: List of additional reference links
            additional_docs: Additional documentation text
            qa_responses: List of question-answer pairs
            
        Returns:
            Audit object containing the findings
        """
        try:
            # Initialize optional parameters
            additional_links = additional_links or []
            qa_responses = qa_responses or []
            
            # Format QA pairs for the prompt
            qa_formatted = ""
            if qa_responses:
                qa_formatted = "## Q&A Information\n"
                for qa in qa_responses:
                    qa_formatted += f"Q: {qa.question}\nA: {qa.answer}\n\n"
            
            # Format additional links
            links_formatted = ""
            if additional_links:
                links_formatted = "## Additional References\n"
                for link in additional_links:
                    links_formatted += f"- {link}\n"
            
            # Format additional documentation
            additional_docs_formatted = ""
            if additional_docs:
                additional_docs_formatted = f"## Additional Documentation\n{additional_docs}\n"
            
            # Prepare the audit prompt with all information
            audit_prompt = AUDIT_PROMPT.format(
                contracts=contracts,
                docs=docs,
                additional_links=links_formatted,
                additional_docs=additional_docs_formatted,
                qa_responses=qa_formatted
            )
            
            # Send single request to OpenAI
            logger.info("Sending audit request to OpenAI")
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert Solidity smart contract auditor."},
                    {"role": "user", "content": audit_prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            # Extract and parse the JSON response
            result_text = response.choices[0].message.content
            logger.debug(f"Received audit response from OpenAI")
            
            try:
                # Parse the JSON response
                audit_result = json.loads(result_text)
                
                # Validate using Pydantic model
                validated_result = Audit(**audit_result)
                
                findings_dict = [finding.model_dump(mode="json") for finding in validated_result.findings]
                logger.info(f"Audit result: {json.dumps(findings_dict, indent=2)}")

                logger.info(f"Audit completed successfully with {len(validated_result.findings)} findings")
                return validated_result
            except json.JSONDecodeError as json_err:
                logger.error(f"Failed to parse JSON response: {json_err}")
                logger.debug(f"Raw response: {result_text}")
                return Audit(findings=[])
            except Exception as validation_err:
                logger.error(f"Validation error with audit response: {validation_err}")
                return Audit(findings=[])
                
        except Exception as e:
            logger.error(f"Error during audit: {str(e)}", exc_info=True)
            return Audit(findings=[])