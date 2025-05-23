from pydantic import BaseModel
from typing import Optional, List

class QAPair(BaseModel):
    """Model for a question-answer pair."""
    question: str
    answer: str

class TaskResponse(BaseModel):
    """Response model for task creation."""
    id: str
    taskId: str
    projectRepo: Optional[str] = None
    title: str
    description: str
    bounty: Optional[str] = None
    status: str
    startTime: Optional[str] = None
    deadline: Optional[str] = None
    selectedBranch: Optional[str] = None
    selectedFiles: Optional[List[str]] = []
    selectedDocs: Optional[List[str]] = []
    additionalLinks: Optional[List[str]] = []
    additionalDocs: Optional[str] = None
    qaResponses: Optional[List[QAPair]] = []