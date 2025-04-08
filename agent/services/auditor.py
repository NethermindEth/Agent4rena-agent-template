"""
Solidity code auditor service.
"""
import re
import uuid
import logging
from typing import List, Dict, Any, Optional
import openai
from openai import OpenAI

from agent.models.solidity_file import SolidityFile
from agent.models.audit_result import AuditResult, Vulnerability, VulnerabilityLocation
from agent.data.vulnerability_database import get_all_vulnerabilities, get_vulnerability
from agent.services.cvss_calculator import CVSSCalculator
from agent.services.code_analyzer import analyze_solidity_code

logger = logging.getLogger(__name__)


class SolidityAuditor:
    """Service for auditing Solidity code."""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", api_base_url: Optional[str] = None):
        """
        Initialize the auditor.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use
            api_base_url: Base URL for OpenAI API
        """
        self.api_key = api_key
        self.model = model
        self.api_base_url = api_base_url
        
        # Initialize OpenAI client
        client_args = {"api_key": api_key}
        if api_base_url:
            client_args["base_url"] = api_base_url
        
        self.client = OpenAI(**client_args)
        
        # Load vulnerability database
        self.vulnerabilities = get_all_vulnerabilities()
        logger.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities from database")
    
    def audit_files(self, files: List[SolidityFile]) -> str:
        """
        Audit a list of Solidity files.
        
        Args:
            files: List of Solidity files to audit
            
        Returns:
            Audit results as a string
        """
        logger.info(f"Auditing {len(files)} Solidity files")
        
        # First, perform pattern-based analysis
        pattern_results = self._pattern_analysis(files)
        
        # Then, use AI to analyze the code
        ai_results = self._ai_analysis(files, pattern_results)
        
        # Combine results and format
        combined_results = self._combine_results(pattern_results, ai_results, files)
        
        # Format results as text
        return self._format_results(combined_results)
    
    def _pattern_analysis(self, files: List[SolidityFile]) -> List[Dict[str, Any]]:
        """
        Perform pattern-based analysis on Solidity files.
        
        Args:
            files: List of Solidity files to analyze
            
        Returns:
            List of potential vulnerabilities
        """
        results = []
        
        for file in files:
            # Analyze code structure
            analysis = analyze_solidity_code(file.content)
            
            # Check for vulnerability patterns
            for vuln in self.vulnerabilities:
                for pattern in vuln.detection_patterns:
                    matches = re.finditer(pattern.pattern, file.content)
                    
                    for match in matches:
                        # Get context around the match
                        start_pos = match.start()
                        end_pos = match.end()
                        
                        # Find line numbers
                        lines = file.content.split('\n')
                        line_start = 1
                        char_count = 0
                        
                        for i, line in enumerate(lines):
                            if char_count + len(line) + 1 > start_pos:
                                line_start = i + 1
                                break
                            char_count += len(line) + 1
                        
                        line_end = line_start
                        for i in range(line_start - 1, len(lines)):
                            if char_count + len(lines[i]) + 1 > end_pos:
                                line_end = i + 1
                                break
                            char_count += len(lines[i]) + 1
                        
                        # Get code snippet
                        context_start = max(0, line_start - pattern.context_lines - 1)
                        context_end = min(len(lines), line_end + pattern.context_lines)
                        code_snippet = '\n'.join(lines[context_start:context_end])
                        
                        # Find function and contract name
                        function_name = None
                        contract_name = None
                        
                        for contract in analysis.get('contracts', []):
                            if contract['line_start'] <= line_start <= contract['line_end']:
                                contract_name = contract['name']
                                
                                for func in contract.get('functions', []):
                                    if func['line_start'] <= line_start <= func['line_end']:
                                        function_name = func['name']
                                        break
                                
                                break
                        
                        # Add to results
                        results.append({
                            'vulnerability': vuln,
                            'file': file.path,
                            'line_start': line_start,
                            'line_end': line_end,
                            'code_snippet': code_snippet,
                            'function_name': function_name,
                            'contract_name': contract_name,
                            'pattern_description': pattern.description
                        })
        
        return results
    
    def _ai_analysis(self, files: List[SolidityFile], pattern_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Use AI to analyze Solidity files.
        
        Args:
            files: List of Solidity files to analyze
            pattern_results: Results from pattern analysis
            
        Returns:
            List of potential vulnerabilities
        """
        ai_results = []
        
        # Prepare context for AI
        context = "You are a Solidity security expert. Analyze the following smart contracts for security vulnerabilities.\n\n"
        
        # Add information about known vulnerabilities
        context += "Known vulnerability patterns to look for:\n"
        for vuln in self.vulnerabilities:
            context += f"- {vuln.name}: {vuln.description}\n"
        
        context += "\nHistorical examples of exploits:\n"
        for vuln in self.vulnerabilities:
            for example in vuln.historical_examples:
                context += f"- {example}\n"
        
        # Add code to analyze
        for file in files:
            context += f"\n\nFile: {file.path}\n```solidity\n{file.content}\n```\n"
        
        # Add pattern analysis results
        if pattern_results:
            context += "\n\nPotential issues identified by pattern analysis:\n"
            for result in pattern_results:
                context += f"- {result['vulnerability'].name} in {result['file']} at lines {result['line_start']}-{result['line_end']} ({result['pattern_description']})\n"
        
        # Prepare prompt for AI
        prompt = context + "\n\nAnalyze these contracts for security vulnerabilities. For each vulnerability found, provide:\n"
        prompt += "1. The vulnerability name and type\n"
        prompt += "2. A detailed description of the vulnerability\n"
        prompt += "3. The exact location (file, line numbers, function/contract)\n"
        prompt += "4. The potential impact of the vulnerability\n"
        prompt += "5. A specific code example showing how to fix the vulnerability\n"
        prompt += "6. Severity assessment (CRITICAL, HIGH, MEDIUM, LOW)\n"
        
        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a Solidity security expert specializing in smart contract audits."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            
            # Parse AI response
            ai_analysis = response.choices[0].message.content
            
            # Extract vulnerabilities from AI response
            vulnerabilities = self._parse_ai_response(ai_analysis, files)
            ai_results.extend(vulnerabilities)
            
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {str(e)}")
        
        return ai_results
    
    def _parse_ai_response(self, ai_response: str, files: List[SolidityFile]) -> List[Dict[str, Any]]:
        """
        Parse AI response to extract vulnerabilities.
        
        Args:
            ai_response: AI response text
            files: List of Solidity files
            
        Returns:
            List of vulnerabilities
        """
        results = []
        
        # Simple parsing logic - can be improved with more sophisticated parsing
        sections = re.split(r'\n\s*\d+\.', ai_response)
        
        for section in sections[1:]:  # Skip the first section which is usually empty
            try:
                # Extract vulnerability name
                name_match = re.search(r'^(.*?)(?:\(|:|\n)', section)
                if not name_match:
                    continue
                
                name = name_match.group(1).strip()
                
                # Extract description
                desc_match = re.search(r'(?:Description|description):\s*(.*?)(?:\n\s*(?:Location|File|Impact|Severity|Remediation)|\Z)', section, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else ""
                
                # Extract location
                loc_match = re.search(r'(?:Location|File):\s*(.*?)(?:\n\s*(?:Impact|Severity|Remediation)|\Z)', section, re.DOTALL)
                location = loc_match.group(1).strip() if loc_match else ""
                
                # Extract file path and line numbers
                file_path = None
                line_start = 1
                line_end = 1
                contract_name = None
                function_name = None
                
                file_match = re.search(r'(?:File|In):\s*([\w\./\\-]+)', location)
                if file_match:
                    file_path = file_match.group(1).strip()
                
                contract_match = re.search(r'(?:Contract|In):\s*(\w+)', location)
                if contract_match:
                    contract_name = contract_match.group(1).strip()
                
                function_match = re.search(r'(?:Function|Method):\s*(\w+)', location)
                if function_match:
                    function_name = function_match.group(1).strip()
                
                line_match = re.search(r'(?:Lines?|line):\s*(\d+)(?:\s*-\s*(\d+))?', location)
                if line_match:
                    line_start = int(line_match.group(1))
                    line_end = int(line_match.group(2)) if line_match.group(2) else line_start
                
                # Extract impact
                impact_match = re.search(r'(?:Impact|Potential impact):\s*(.*?)(?:\n\s*(?:Remediation|Recommended fix|Severity)|\Z)', section, re.DOTALL)
                impact = impact_match.group(1).strip() if impact_match else ""
                
                # Extract remediation
                remediation_match = re.search(r'(?:Remediation|Recommended fix):\s*(.*?)(?:\n\s*(?:Severity|References)|\Z)', section, re.DOTALL)
                remediation = remediation_match.group(1).strip() if remediation_match else ""
                
                # Extract severity
                severity_match = re.search(r'(?:Severity|THREAT LEVEL):\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)', section, re.IGNORECASE)
                severity = severity_match.group(1).upper() if severity_match else "MEDIUM"
                
                # Find matching file
                matching_file = None
                for file in files:
                    if file_path and file_path in file.path:
                        matching_file = file
                        break
                
                if not matching_file and files:
                    # If no matching file found, use the first file
                    matching_file = files[0]
                
                # Extract code snippet
                code_snippet = ""
                if matching_file:
                    lines = matching_file.content.split('\n')
                    start_idx = max(0, line_start - 3 - 1)
                    end_idx = min(len(lines), line_end + 3)
                    code_snippet = '\n'.join(lines[start_idx:end_idx])
                
                # Find matching vulnerability in database
                matching_vuln = None
                for vuln in self.vulnerabilities:
                    if vuln.name.lower() in name.lower() or name.lower() in vuln.name.lower():
                        matching_vuln = vuln
                        break
                
                # Calculate CVSS score if not found in database
                cvss_score = 5.0  # Default medium score
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
                
                if matching_vuln:
                    cvss_score = matching_vuln.cvss_score
                    cvss_vector = matching_vuln.cvss_vector
                else:
                    # Map severity to CVSS score
                    if severity == "CRITICAL":
                        cvss_score = 9.5
                        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                    elif severity == "HIGH":
                        cvss_score = 8.0
                        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    elif severity == "MEDIUM":
                        cvss_score = 5.5
                        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                    elif severity == "LOW":
                        cvss_score = 3.5
                        cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
                
                # Add to results
                results.append({
                    'name': name,
                    'description': description,
                    'file': matching_file.path if matching_file else file_path or "Unknown",
                    'line_start': line_start,
                    'line_end': line_end,
                    'code_snippet': code_snippet,
                    'function_name': function_name,
                    'contract_name': contract_name,
                    'impact': impact,
                    'remediation': remediation,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'references': matching_vuln.references if matching_vuln else [],
                    'historical_examples': matching_vuln.historical_examples if matching_vuln else []
                })
                
            except Exception as e:
                logger.error(f"Error parsing AI response section: {str(e)}")
        
        return results
    
    def _combine_results(self, pattern_results: List[Dict[str, Any]], ai_results: List[Dict[str, Any]], 
                         files: List[SolidityFile]) -> AuditResult:
        """
        Combine pattern analysis and AI analysis results.
        
        Args:
            pattern_results: Results from pattern analysis
            ai_results: Results from AI analysis
            files: List of Solidity files
            
        Returns:
            Combined audit results
        """
        # Create a unique ID for this audit
        audit_id = str(uuid.uuid4())
        
        # Combine and deduplicate results
        all_vulnerabilities = []
        seen_vulnerabilities = set()
        
        # Process AI results first (they're usually more accurate)
        for result in ai_results:
            # Create a unique key for this vulnerability
            key = f"{result['name']}:{result['file']}:{result['line_start']}"
            
            if key not in seen_vulnerabilities:
                seen_vulnerabilities.add(key)
                
                # Create vulnerability location
                location = VulnerabilityLocation(
                    file=result['file'],
                    line_start=result['line_start'],
                    line_end=result['line_end'],
                    code_snippet=result['code_snippet'],
                    function_name=result['function_name'],
                    contract_name=result['contract_name']
                )
                
                # Create vulnerability
                vulnerability = Vulnerability(
                    id=f"VULN-{len(all_vulnerabilities) + 1}",
                    name=result['name'],
                    description=result['description'],
                    severity=result['severity'],
                    cvss_score=result['cvss_score'],
                    cvss_vector=result['cvss_vector'],
                    locations=[location],
                    impact=result['impact'],
                    remediation=result['remediation'],
                    references=result['references'],
                    historical_examples=result['historical_examples']
                )
                
                all_vulnerabilities.append(vulnerability)
        
        # Then process pattern results
        for result in pattern_results:
            # Create a unique key for this vulnerability
            key = f"{result['vulnerability'].name}:{result['file']}:{result['line_start']}"
            
            if key not in seen_vulnerabilities:
                seen_vulnerabilities.add(key)
                
                # Create vulnerability location
                location = VulnerabilityLocation(
                    file=result['file'],
                    line_start=result['line_start'],
                    line_end=result['line_end'],
                    code_snippet=result['code_snippet'],
                    function_name=result['function_name'],
                    contract_name=result['contract_name']
                )
                
                # Create vulnerability
                vulnerability = Vulnerability(
                    id=f"VULN-{len(all_vulnerabilities) + 1}",
                    name=result['vulnerability'].name,
                    description=result['vulnerability'].description,
                    severity=CVSSCalculator.get_severity(result['vulnerability'].cvss_score),
                    cvss_score=result['vulnerability'].cvss_score,
                    cvss_vector=result['vulnerability'].cvss_vector,
                    locations=[location],
                    impact=f"This vulnerability could lead to security issues as described in the following historical examples: {', '.join(result['vulnerability'].historical_examples)}",
                    remediation=result['vulnerability'].remediation_example,
                    references=result['vulnerability'].references,
                    historical_examples=result['vulnerability'].historical_examples
                )
                
                all_vulnerabilities.append(vulnerability)
        
        # Create audit result
        audit_result = AuditResult(
            audit_id=audit_id,
            files=[file.path for file in files],
            vulnerabilities=all_vulnerabilities
        )
        
        return audit_result
    
    def _format_results(self, audit_result: AuditResult) -> str:
        """
        Format audit results as a string.
        
        Args:
            audit_result: Audit results
            
        Returns:
            Formatted results
        """
        if not audit_result.vulnerabilities:
            return "No vulnerabilities found."
        
        # Format results
        result = ""
        
        for i, vuln in enumerate(audit_result.vulnerabilities, 1):
            result += f"{i}. {vuln.name}\n"
            result += f"• Description: {vuln.description}\n"
            
            for loc in vuln.locations:
                result += f"• Location: In {loc.file}"
                if loc.contract_name:
                    result += f", contract {loc.contract_name}"
                if loc.function_name:
                    result += f", function {loc.function_name}"
                result += f", lines {loc.line_start}-{loc.line_end}.\n"
            
            result += f"• Potential impact: {vuln.impact}\n"
            result += f"• Recommended fix: {vuln.remediation}\n"
            
            if vuln.references:
                result += "• References:\n"
                for ref in vuln.references:
                    result += f"  - {ref}\n"
            
            result += "\n"
        
        result += f"THREAT LEVEL: {max([vuln.severity for vuln in audit_result.vulnerabilities])}"
        
        return result