"""
Solidity code analyzer.
"""
import re
from typing import Dict, List, Any


def analyze_solidity_code(code: str) -> Dict[str, Any]:
    """
    Analyze Solidity code to extract structure information.
    
    Args:
        code: Solidity code to analyze
        
    Returns:
        Dictionary with code structure information
    """
    result = {
        "contracts": [],
        "interfaces": [],
        "libraries": []
    }
    
    # Split code into lines
    lines = code.split('\n')
    
    # Find contracts, interfaces, and libraries
    contract_pattern = r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([\w\s,]+))?'
    
    current_contract = None
    current_contract_type = None
    current_contract_start = 0
    current_contract_end = 0
    brace_count = 0
    
    for i, line in enumerate(lines):
        # Check for contract/interface/library definition
        contract_match = re.search(contract_pattern, line)
        if contract_match and not current_contract:
            current_contract_type = contract_match.group(1)
            current_contract = contract_match.group(2)
            inheritance = contract_match.group(3) if contract_match.group(3) else ""
            current_contract_start = i + 1
            
            if "{" in line:
                brace_count += line.count("{") - line.count("}")
        
        # Count braces to track contract body
        elif current_contract:
            brace_count += line.count("{") - line.count("}")
            
            if brace_count == 0:
                current_contract_end = i + 1
                
                # Add contract to result
                contract_info = {
                    "name": current_contract,
                    "type": current_contract_type,
                    "line_start": current_contract_start,
                    "line_end": current_contract_end,
                    "functions": [],
                    "state_variables": []
                }
                
                # Extract functions and state variables
                contract_code = '\n'.join(lines[current_contract_start-1:current_contract_end])
                contract_info["functions"] = _extract_functions(contract_code, current_contract_start)
                contract_info["state_variables"] = _extract_state_variables(contract_code, current_contract_start)
                
                if current_contract_type == "contract":
                    result["contracts"].append(contract_info)
                elif current_contract_type == "interface":
                    result["interfaces"].append(contract_info)
                elif current_contract_type == "library":
                    result["libraries"].append(contract_info)
                
                current_contract = None
                current_contract_type = None
        
        # If we're not in a contract yet, check for braces
        elif "{" in line:
            brace_count += line.count("{") - line.count("}")
    
    return result


def _extract_functions(code: str, line_offset: int) -> List[Dict[str, Any]]:
    """
    Extract functions from Solidity code.
    
    Args:
        code: Solidity code to analyze
        line_offset: Line number offset
        
    Returns:
        List of functions
    """
    functions = []
    
    # Function pattern
    function_pattern = r'function\s+(\w+)\s*\(([^)]*)\)(?:\s+(\w+))?(?:\s+(\w+))?(?:\s+returns\s*\(([^)]*)\))?'
    
    # Find all functions
    lines = code.split('\n')
    current_function = None
    current_function_start = 0
    current_function_end = 0
    brace_count = 0
    in_function = False
    
    for i, line in enumerate(lines):
        # Check for function definition
        if not in_function:
            function_match = re.search(function_pattern, line)
            if function_match:
                current_function = function_match.group(1)
                params = function_match.group(2)
                visibility = function_match.group(3)
                mutability = function_match.group(4)
                returns = function_match.group(5)
                
                current_function_start = i + line_offset
                in_function = True
                
                if "{" in line:
                    brace_count += line.count("{") - line.count("}")
        
        # Count braces to track function body
        elif in_function:
            brace_count += line.count("{") - line.count("}")
            
            if brace_count == 0 or ";" in line and brace_count == 0:
                current_function_end = i + line_offset
                
                # Add function to result
                function_info = {
                    "name": current_function,
                    "line_start": current_function_start,
                    "line_end": current_function_end
                }
                
                functions.append(function_info)
                
                current_function = None
                in_function = False
        
        # If we're not in a function yet, check for braces
        elif "{" in line and not in_function:
            brace_count += line.count("{") - line.count("}")
    
    return functions


def _extract_state_variables(code: str, line_offset: int) -> List[Dict[str, Any]]:
    """
    Extract state variables from Solidity code.
    
    Args:
        code: Solidity code to analyze
        line_offset: Line number offset
        
    Returns:
        List of state variables
    """
    variables = []
    
    # State variable pattern
    variable_pattern = r'^\s*([\w\[\]]+)\s+(public|private|internal|)?\s*([\w]+)(?:\s*=\s*([^;]+))?;'
    
    # Find all state variables
    lines = code.split('\n')
    
    for i, line in enumerate(lines):
        # Skip comments and function bodies
        if line.strip().startswith('//') or line.strip().startswith('/*') or '{' in line:
            continue
        
        # Check for state variable definition
        variable_match = re.search(variable_pattern, line)
        if variable_match:
            var_type = variable_match.group(1)
            visibility = variable_match.group(2) or 'internal'  # Default visibility
            name = variable_match.group(3)
            initial_value = variable_match.group(4)
            
            # Add variable to result
            variable_info = {
                "name": name,
                "type": var_type,
                "visibility": visibility,
                "line": i + line_offset,
                "initial_value": initial_value
            }
            
            variables.append(variable_info)
    
    return variables