"""
CVSS (Common Vulnerability Scoring System) calculator for Solidity vulnerabilities.
"""
from typing import Dict, Tuple


class CVSSCalculator:
    """
    Calculator for CVSS scores based on vulnerability characteristics.
    Implements a simplified version of CVSS v3.1.
    """
    
    # Base metrics
    ATTACK_VECTOR = {
        "N": 0.85,  # Network
        "A": 0.62,  # Adjacent
        "L": 0.55,  # Local
        "P": 0.2    # Physical
    }
    
    ATTACK_COMPLEXITY = {
        "L": 0.77,  # Low
        "H": 0.44   # High
    }
    
    PRIVILEGES_REQUIRED = {
        "N": 0.85,  # None
        "L": 0.62,  # Low
        "H": 0.27   # High
    }
    
    USER_INTERACTION = {
        "N": 0.85,  # None
        "R": 0.62   # Required
    }
    
    SCOPE = {
        "U": 0.0,   # Unchanged
        "C": 1.0    # Changed
    }
    
    IMPACT_METRICS = {
        "N": 0.0,   # None
        "L": 0.22,  # Low
        "H": 0.56   # High
    }
    
    @staticmethod
    def calculate_base_score(vector: str) -> Tuple[float, Dict[str, str]]:
        """
        Calculate CVSS base score from vector string.
        
        Args:
            vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
            
        Returns:
            Tuple of (score, parsed_metrics)
        """
        # Parse vector
        parts = vector.split("/")
        metrics = {}
        
        for part in parts:
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value
        
        # Extract metrics
        av = metrics.get("AV", "N")  # Attack Vector
        ac = metrics.get("AC", "L")  # Attack Complexity
        pr = metrics.get("PR", "N")  # Privileges Required
        ui = metrics.get("UI", "N")  # User Interaction
        s = metrics.get("S", "U")    # Scope
        c = metrics.get("C", "N")    # Confidentiality
        i = metrics.get("I", "N")    # Integrity
        a = metrics.get("A", "N")    # Availability
        
        # Calculate Impact Sub-Score (ISS)
        iss = 1 - (
            (1 - CVSSCalculator.IMPACT_METRICS[c]) *
            (1 - CVSSCalculator.IMPACT_METRICS[i]) *
            (1 - CVSSCalculator.IMPACT_METRICS[a])
        )
        
        # Calculate Impact
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        
        # Calculate Exploitability
        exploitability = 8.22 * CVSSCalculator.ATTACK_VECTOR[av] * CVSSCalculator.ATTACK_COMPLEXITY[ac] * \
                        CVSSCalculator.PRIVILEGES_REQUIRED[pr] * CVSSCalculator.USER_INTERACTION[ui]
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0
        else:
            if s == "U":
                base_score = min(impact + exploitability, 10)
            else:
                base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round to 1 decimal place
        base_score = round(base_score, 1)
        
        return base_score, metrics
    
    @staticmethod
    def get_severity(score: float) -> str:
        """Get severity rating from CVSS score."""
        if score == 0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"
    
    @staticmethod
    def vector_to_readable(vector: str) -> Dict[str, str]:
        """Convert CVSS vector to human-readable format."""
        parts = vector.split("/")
        result = {}
        
        mapping = {
            "AV": {
                "N": "Network",
                "A": "Adjacent",
                "L": "Local",
                "P": "Physical"
            },
            "AC": {
                "L": "Low",
                "H": "High"
            },
            "PR": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "UI": {
                "N": "None",
                "R": "Required"
            },
            "S": {
                "U": "Unchanged",
                "C": "Changed"
            },
            "C": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "I": {
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "A": {
                "N": "None",
                "L": "Low",
                "H": "High"
            }
        }
        
        for part in parts:
            if ":" in part:
                key, value = part.split(":")
                if key in mapping and value in mapping[key]:
                    result[key] = mapping[key][value]
                else:
                    result[key] = value
        
        return result