from pydantic import BaseModel, Field
from typing import List, Optional


class ToolPermission(BaseModel):
    name: str
    network_access: bool = False
    file_system_write: bool = False
    file_system_read: bool = False
    allowed_domains: List[str] = Field(default_factory=list)


class SkillManifest(BaseModel):
    id: str
    name: str
    version: str
    author: str
    signature: Optional[str] = None
    permissions: ToolPermission
    instructions: str