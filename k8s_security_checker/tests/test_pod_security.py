import unittest
from unittest.mock import Mock, patch
from kubernetes import client
from ..checks.pod_security import PodSecurityChecker

class TestPodSecurityChecker(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.mock_client = Mock(spec=client.ApiClient)
        self.checker = PodSecurityChecker(self.mock_client)

    def _create_mock_container(self, **kwargs):
        """Helper to create a mock container with specific attributes."""
        container = Mock()
        container.name = kwargs.get('name', 'test-container')
        container.image = kwargs.get('image', 'nginx:latest')
        
        # Security context
        security_context = Mock()
        security_context.privileged = kwargs.get('privileged', False)
        security_context.run_as_non_root = kwargs.get('run_as_non_root', None)
        container.security_context = kwargs.get('security_context', security_context)
        
        # Resources
        resources = Mock()
        resources.limits = kwargs.get('resource_limits', {'cpu': '100m', 'memory': '128Mi'})
        container.resources = kwargs.get('resources', resources)
        
        # Volume mounts
        container.volume_mounts = kwargs.get('volume_mounts', [])
        
        return container

    def _create_mock_pod(self, containers):
        """Helper to create a mock pod with specific containers."""
        pod = Mock()
        pod.metadata.name = 'test-pod'
        pod.spec.containers = containers
        return pod

    def test_root_container_detection(self):
        """Test detection of containers running as root."""
        # Create a container running as root
        container = self._create_mock_container(run_as_non_root=False)
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'HIGH')
        self.assertIn('running as root', issues[0]['issue'])

    def test_privileged_container_detection(self):
        """Test detection of privileged containers."""
        # Create a privileged container
        container = self._create_mock_container(privileged=True)
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'CRITICAL')
        self.assertIn('privileged mode', issues[0]['issue'])

    def test_dind_container_detection(self):
        """Test detection of Docker-in-Docker containers."""
        # Create a DinD container
        container = self._create_mock_container(image='docker:dind')
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'CRITICAL')
        self.assertIn('Docker-in-Docker', issues[0]['issue'])

    def test_sensitive_mount_detection(self):
        """Test detection of sensitive path mounts."""
        # Create a container with sensitive mount
        volume_mount = Mock()
        volume_mount.mount_path = '/etc/sensitive'
        container = self._create_mock_container(volume_mounts=[volume_mount])
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'HIGH')
        self.assertIn('Sensitive path mounted', issues[0]['issue'])

    def test_crypto_miner_detection(self):
        """Test detection of potential crypto mining containers."""
        # Create a container with crypto mining image
        container = self._create_mock_container(image='xmrig/monero-miner')
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'CRITICAL')
        self.assertIn('crypto mining', issues[0]['issue'])

    def test_missing_resource_limits(self):
        """Test detection of missing resource limits."""
        # Create a container without resource limits
        container = self._create_mock_container(resources=None)
        pod = self._create_mock_pod([container])
        
        # Mock the Kubernetes API response
        self.checker.v1.list_namespaced_pod.return_value.items = [pod]
        
        # Run the check
        issues = self.checker.run()
        
        # Verify the issues
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['severity'], 'MEDIUM')
        self.assertIn('resource limits', issues[0]['issue'])

if __name__ == '__main__':
    unittest.main() 