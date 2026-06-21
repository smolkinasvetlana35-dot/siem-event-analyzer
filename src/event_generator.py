"""
Модуль для генерации тестовых событий безопасности.
Использует библиотеку Faker для создания реалистичных данных.
"""

import json
import random
import os
from datetime import datetime, timedelta
from collections import namedtuple
from typing import List, Dict, Any
from faker import Faker

# Создаем именованный кортеж для событий
Event = namedtuple('Event', ['timestamp', 'src_ip', 'dst_ip', 'protocol',
                             'port', 'event_type', 'severity', 'description'])

# Типы событий и их описания
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


class EventGenerator:
    """
    Генератор событий безопасности.

    Attributes:
        fake (Faker): Экземпляр Faker для генерации данных.
        event_count (int): Количество генерируемых событий.
    """

    def __init__(self, event_count: int = 1000):
        """
        Инициализация генератора.

        Args:
            event_count: Количество событий для генерации.
        """
        self.fake = Faker()
        self.event_count = event_count
        self._generated_events = []

    def generate_events(self) -> List[Event]:
        """
        Генерация событий безопасности.

        Returns:
            List[Event]: Список сгенерированных событий.
        """
        self._generated_events = []

        for _ in range(self.event_count):
            event_type = random.choice(list(EVENT_TYPES.keys()))

            # Генерация порта в зависимости от протокола
            protocol = random.choice(PROTOCOLS)
            if protocol in ['TCP', 'UDP']:
                port = random.choice([22, 23, 25, 53, 80, 110, 123, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443])
            else:
                port = None

            event = Event(
                timestamp=self.fake.date_time_between(start_date='-30d', end_date='now'),
                src_ip=self.fake.ipv4(),
                dst_ip=self.fake.ipv4(),
                protocol=protocol,
                port=port,
                event_type=event_type,
                severity=random.randint(1, 10),
                description=EVENT_TYPES[event_type] + ' - ' + self.fake.sentence(nb_words=5)
            )
            self._generated_events.append(event)

        return self._generated_events

    def save_to_json(self, filename: str = None) -> None:
        """
        Сохранение сгенерированных событий в JSON файл.

        Args:
            filename: Путь к файлу для сохранения.
        """
        if filename is None:
            # Определяем корневую директорию проекта
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            data_dir = os.path.join(project_root, 'data')
            os.makedirs(data_dir, exist_ok=True)
            filename = os.path.join(data_dir, 'events.json')

        events_dict = [e._asdict() for e in self._generated_events]
        # Преобразование datetime в строку для JSON
        for event in events_dict:
            event['timestamp'] = event['timestamp'].isoformat()
            event['port'] = str(event['port']) if event['port'] is not None else None

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events_dict, f, ensure_ascii=False, indent=2)

        print(f"События сохранены в {filename}")