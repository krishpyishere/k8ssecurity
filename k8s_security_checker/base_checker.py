from typing import List, Dict
from kubernetes import client

class BaseChecker:
    """Base class for all security checkers."""
    
    def __init__(self, k8s_client: client.ApiClient = None):
        """Initialize the checker with a Kubernetes client."""
        self.k8s_client = k8s_client or self._get_default_client()
        self.v1 = client.CoreV1Api(self.k8s_client)
        self.apps_v1 = client.AppsV1Api(self.k8s_client)
        self.rbac_v1 = client.RbacAuthorizationV1Api(self.k8s_client)
        self.networking_v1 = client.NetworkingV1Api(self.k8s_client)

    def _get_default_client(self) -> client.ApiClient:
        """Get a default Kubernetes client."""
        try:
            client.Configuration.set_default(client.Configuration())
            config = client.Configuration()
            client.Configuration.set_default(config)
            return client.ApiClient(client.Configuration())
        except Exception as e:
            raise RuntimeError(f"Failed to create Kubernetes client: {e}")

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run the security check.
        
        Args:
            namespace: The Kubernetes namespace to check.
            
        Returns:
            List of issues found, each issue is a dict with keys:
            - pod: Pod/resource name
            - container: Container/component name
            - issue: Description of the issue
            - severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO
        """
        raise NotImplementedError("Subclasses must implement run()") 