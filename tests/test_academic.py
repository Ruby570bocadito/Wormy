"""
Academic Unit Tests for ML Network Worm
Unit testing demonstrating software engineering practices
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestWormCore(unittest.TestCase):
    """Test cases for WormCore class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_config = Mock()
        self.mock_config.validate.return_value = True
        self.mock_config.network.target_ranges = ['192.168.1.0/24']
        self.mock_config.evasion.stealth_mode = True
        self.mock_config.ml.use_pretrained = False
        self.mock_config.propagation.max_infections = 10
        self.mock_config.safety.max_runtime_hours = 2
        self.mock_config.safety.auto_destruct_time = 2
        self.mock_config.safety.geofence_enabled = False
        self.mock_config.safety.kill_switch_code = "TEST123"
        
    def test_initialization(self):
        """Test worm core initialization"""
        with patch('worm_core.Config', return_value=self.mock_config):
            with patch('worm_core.IntelligentScanner'):
                with patch('worm_core.ExploitManager'):
                    with patch('worm_core.IDSDetector'):
                        with patch('worm_core.StealthEngine'):
                            with patch('worm_core.PropagationAgent'):
                                from worm_core import WormCore
                                
                                worm = WormCore(config_file="config_simulation.yaml")
                                
                                self.assertIsNotNone(worm)
                                self.assertIsNotNone(worm.config)
                                self.assertEqual(len(worm.infected_hosts), 0)
    
    def test_kill_switch_activation(self):
        """Test kill switch with correct code"""
        with patch('worm_core.Config', return_value=self.mock_config):
            with patch('worm_core.IntelligentScanner'):
                with patch('worm_core.ExploitManager'):
                    with patch('worm_core.IDSDetector'):
                        with patch('worm_core.StealthEngine'):
                            with patch('worm_core.PropagationAgent'):
                                from worm_core import WormCore
                                
                                worm = WormCore(config_file="config_simulation.yaml")
                                worm.activate_kill_switch("TEST123")
                                
                                self.assertTrue(worm.kill_switch_activated)
    
    def test_kill_switch_invalid_code(self):
        """Test kill switch with wrong code"""
        with patch('worm_core.Config', return_value=self.mock_config):
            with patch('worm_core.IntelligentScanner'):
                with patch('worm_core.ExploitManager'):
                    with patch('worm_core.IDSDetector'):
                        with patch('worm_core.StealthEngine'):
                            with patch('worm_core.PropagationAgent'):
                                from worm_core import WormCore
                                
                                worm = WormCore(config_file="config_simulation.yaml")
                                worm.activate_kill_switch("WRONG")
                                
                                self.assertFalse(worm.kill_switch_activated)


class TestExploitManager(unittest.TestCase):
    """Test cases for ExploitManager"""
    
    def test_exploit_loading(self):
        """Test that exploits are loaded"""
        mock_config = Mock()
        mock_config.exploit.enable_smb = True
        mock_config.exploit.enable_ssh = True
        mock_config.exploit.enable_web = True
        mock_config.exploit.credential_wordlist = "wordlists/credentials.txt"
        mock_config.exploit.exploit_timeout = 10
        
        with patch('exploits.exploit_manager.logger'):
            from exploits.exploit_manager import ExploitManager
            
            manager = ExploitManager(mock_config)
            
            self.assertIsNotNone(manager.exploits)
            self.assertGreater(len(manager.exploits), 0)
    
    def test_credential_database(self):
        """Test credential database contains only test credentials"""
        mock_config = Mock()
        mock_config.exploit.enable_smb = True
        mock_config.exploit.enable_ssh = True
        mock_config.exploit.enable_web = True
        mock_config.exploit.credential_wordlist = "wordlists/credentials.txt"
        mock_config.exploit.exploit_timeout = 10
        
        with patch('exploits.exploit_manager.logger'):
            from exploits.exploit_manager import ExploitManager
            
            manager = ExploitManager(mock_config)
            
            for username, password in manager.credentials_db:
                self.assertIn(username.lower(), ['test', 'guest', 'demo'])
                self.assertIn(password.lower(), ['test', 'guest', 'demo', 'test123'])


class TestNetworkScanner(unittest.TestCase):
    """Test cases for network scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner can be initialized"""
        mock_config = Mock()
        mock_config.network.target_ranges = ['192.168.1.0/24']
        mock_config.scanner.scan_timeout = 5
        mock_config.scanner.concurrent_scans = 10
        
        with patch('scanner.intelligent_scanner.logger'):
            try:
                from scanner.intelligent_scanner import IntelligentScanner
                scanner = IntelligentScanner(mock_config, use_ml=True)
                self.assertIsNotNone(scanner)
            except ImportError as e:
                self.skipTest(f"Scanner module not available: {e}")


class TestRLAgent(unittest.TestCase):
    """Test cases for RL Agent"""
    
    def test_agent_creation(self):
        """Test RL agent can be created"""
        try:
            from rl_engine.propagation_agent import PropagationAgent
            
            agent = PropagationAgent(state_size=10, action_size=5, use_dqn=False)
            
            self.assertIsNotNone(agent)
            self.assertEqual(agent.state_size, 10)
            self.assertEqual(agent.action_size, 5)
        except ImportError:
            self.skipTest("RL Engine module not available")
    
    def test_agent_action_selection(self):
        """Test agent can select actions"""
        try:
            from rl_engine.propagation_agent import PropagationAgent
            
            agent = PropagationAgent(state_size=10, action_size=5, use_dqn=False)
            
            state = [0.1] * 10
            action = agent.act(state)
            
            self.assertIsInstance(action, int)
            self.assertGreaterEqual(action, 0)
            self.assertLess(action, 5)
        except ImportError:
            self.skipTest("RL Engine module not available")


class TestConfigValidation(unittest.TestCase):
    """Test configuration validation"""
    
    def test_config_loads(self):
        """Test configuration can be loaded"""
        try:
            from config import Config
            
            config = Config("config_simulation.yaml")
            
            self.assertIsNotNone(config)
        except ImportError as e:
            self.skipTest(f"Config module not available: {e}")
    
    def test_simulation_config(self):
        """Test simulation config is valid"""
        try:
            from config import Config
            
            config = Config("config_simulation.yaml")
            
            self.assertTrue(config.validate())
            
            self.assertLessEqual(config.propagation.max_infections, 100)
            self.assertLessEqual(config.safety.max_runtime_hours, 4)
        except ImportError:
            self.skipTest("Config module not available")


class TestSafetyMechanisms(unittest.TestCase):
    """Test safety mechanisms"""
    
    def test_max_infections_limit(self):
        """Test max infections limit is respected"""
        mock_config = Mock()
        mock_config.validate.return_value = True
        mock_config.propagation.max_infections = 5
        mock_config.safety.max_runtime_hours = 24
        mock_config.safety.auto_destruct_time = 24
        mock_config.safety.geofence_enabled = False
        mock_config.safety.kill_switch_code = "TEST"
        
        with patch('worm_core.get_local_ip', return_value='192.168.1.1'):
            with patch('worm_core.is_ip_in_range', return_value=True):
                try:
                    from worm_core import WormCore
                    
                    with patch('worm_core.Config', return_value=mock_config):
                        with patch('worm_core.IntelligentScanner'):
                            with patch('worm_core.ExploitManager'):
                                with patch('worm_core.IDSDetector'):
                                    with patch('worm_core.StealthEngine'):
                                        with patch('worm_core.PropagationAgent'):
                                            worm = WormCore()
                                            worm.infected_hosts = {'192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'}
                                            
                                            can_continue = worm.check_safety_constraints()
                                            self.assertFalse(can_continue)
                except ImportError:
                    self.skipTest("Worm core module not available")


if __name__ == '__main__':
    unittest.main()