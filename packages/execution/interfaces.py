from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int

@dataclass
class ExecutionContract:
    contract_id: str
    execution_id: str
    tenant_id: str
    workspace_id: str
    contract_version: str
    target_node_id: str
    scheduler_id: str
    scheduler_version: str
    timestamp: float
    expires_at: float
    nonce: str
    signature: str
    image: str
    command: List[str]
    env: Dict[str, str]
    capabilities: List[str]
    required_region: Optional[str] = None
    required_zone: Optional[str] = None

class ContainerRuntime(ABC):
    """Abstract runtime for executing sandboxed plugins."""
    
    @abstractmethod
    async def execute(
        self, 
        image: str, 
        command: List[str], 
        env: Dict[str, str], 
        capabilities: List[str],
        tenant_id: str
    ) -> ExecutionResult:
        pass

