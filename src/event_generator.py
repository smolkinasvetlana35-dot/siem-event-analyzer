"""
Модуль для генерации тестовых событий безопасности.
"""

import json
import random
import os
from datetime import datetime
from collections import namedtuple
from typing import List
from faker import Faker

# Именованный кортеж для событий
Event = namedtuple('Event', ['timestamp', 'src_ip', 'dst_ip', 'protocol',
                             'port', 'event_type', 'severity', 'description'])

# Типы событий и протоколы
EVENT_TYPES = {
    'login_failure': 'Failed login attempt',
    'login_success': 'Successful login',
    'ssh_connection': 'SSH connection established',
    'dns_query': 'DNS query received',
    'malware_detected': 'Malware detected in traffic',
    'firewall_block': 'Firewall blocked connection',
    'port_scan': 'Port scan detected',
    'sql_injection': 'SQL injection attempt',
    'ddos_attack': 'DDoS attack detected',
    'privilege_escalation': 'Privilege escalation attempt'
}

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
PORTS = [22, 23, 25, 53, 80, 110, 123, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443]


class EventGenerator:
    """Генератор событий безопасности."""

    def __init__(self, event_count: int = 1000):
        self.fake = Faker()
        self.event_count = event_count
        self._events = []

    def generate_events(self) -> List[Event]:
        """Генерация указанного количества событий."""
        self._events = []

        for _ in range(self.event_count):
            event_type = random.choice(list(EVENT_TYPES.keys()))
            protocol = random.choice(PROTOCOLS)
            port = random.choice(PORTS) if protocol in ['TCP', 'UDP'] else None

            event = Event(
                timestamp=self.fake.date_time_between(start_date='-30d', end_date='now'),
                src_ip=self.fake.ipv4(),
                dst_ip=self.fake.ipv4(),
                protocol=protocol,
                port=port,
                event_type=event_type,
                severity=random.randint(1, 10),
                description=f"{EVENT_TYPES[event_type]} - {self.fake.sentence(nb_words=5)}"
            )
            self._events.append(event)

        return self._events

    def save_to_json(self, filename: str = None) -> None:
        """Сохранение событий в JSON файл."""
        if filename is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
            os.makedirs(data_dir, exist_ok=True)
            filename = os.path.join(data_dir, 'events.json')

        # Преобразование namedtuple в словарь с сериализацией datetime
        events_dict = []
        for e in self._events:
            event_dict = e._asdict()
            event_dict['timestamp'] = event_dict['timestamp'].isoformat()
            event_dict['port'] = str(event_dict['port']) if event_dict['port'] is not None else None
            events_dict.append(event_dict)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events_dict, f, ensure_ascii=False, indent=2)

        print(f"События сохранены в {filename}")