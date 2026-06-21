"""
Модуль для анализа событий безопасности с использованием namedtuple.
"""

import json
import logging
import os
from collections import namedtuple, Counter
from datetime import datetime
from typing import List, Set, Dict, Any, Generator, Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('app.log', encoding='utf-8'), logging.StreamHandler()]
)

Event = namedtuple('Event', ['timestamp', 'src_ip', 'dst_ip', 'protocol',
                            'port', 'event_type', 'severity', 'description'])


class EventAnalyzer:
    """Анализатор событий безопасности."""

    def __init__(self, file_path: str = 'data/events.json'):
        self._events: List[Event] = []

        # Определяем пути к файлам
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(project_root, 'data')
        os.makedirs(data_dir, exist_ok=True)

        self._file_path = os.path.join(data_dir, 'events.json') if not os.path.isabs(file_path) else file_path
        self._state_file = os.path.join(data_dir, 'state.json')
        self._report_file = os.path.join(data_dir, 'report.json')

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Загрузка из: {self._file_path}")

    @property
    def events(self) -> List[Event]:
        return self._events

    @events.setter
    def events(self, value: List[Event]) -> None:
        self._events = value

    def load_events_from_file(self) -> Generator[Event, None, None]:
        """Загрузка событий из JSON (генератор)."""
        self.logger.info(f"Загрузка из: {self._file_path}")

        if not os.path.exists(self._file_path):
            raise FileNotFoundError(f"Файл не найден: {self._file_path}")

        with open(self._file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

            if not isinstance(data, list):
                raise ValueError("Файл должен содержать массив")

            for item in data:
                item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                item['port'] = int(item['port']) if item['port'] else None
                event = Event(**item)
                self._events.append(event)
                yield event

    def filter_high_severity(self, threshold: int = 5) -> List[Event]:
        """Фильтрация событий с severity > threshold, сортировка по времени."""
        filtered = [e for e in self._events if e.severity > threshold]
        return sorted(filtered, key=lambda e: e.timestamp)

    def group_by_type(self) -> Dict[str, int]:
        """Группировка событий по типу."""
        return dict(Counter(e.event_type for e in self._events))

    def get_unique_ips(self) -> Set[str]:
        """Извлечение уникальных IP-адресов."""
        unique_ips = set()
        for e in self._events:
            unique_ips.add(e.src_ip)
            unique_ips.add(e.dst_ip)
        return unique_ips

    def demonstrate_immutability(self) -> None:
        """Демонстрация неизменяемости namedtuple."""
        if not self._events:
            print("   Нет событий для демонстрации")
            return

        try:
            e = self._events[0]
            e.severity = 10
        except AttributeError as err:
            print(f"   ✓ Ошибка: {err}")
            print("   Демонстрация успешна: поля namedtuple нельзя изменить")

    def generate_report(self, filename: Optional[str] = None) -> None:
        """Генерация аналитического отчета в JSON."""
        filename = filename or self._report_file
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_events": len(self._events),
            "high_severity_events": len(self.filter_high_severity()),
            "event_types": self.group_by_type(),
            "unique_ips": list(self.get_unique_ips()),
            "immutability_demo": "Namedtuple fields cannot be modified"
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"   Отчет сохранен в {filename}")

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация состояния в словарь."""
        events_dict = []
        for e in self._events:
            d = e._asdict()
            d['timestamp'] = d['timestamp'].isoformat()
            d['port'] = str(d['port']) if d['port'] else None
            events_dict.append(d)

        return {
            'events': events_dict,
            'file_path': self._file_path,
            'event_count': len(self._events),
            'saved_at': datetime.now().isoformat()
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        """Восстановление состояния из словаря."""
        self._events = []
        for d in data.get('events', []):
            d['timestamp'] = datetime.fromisoformat(d['timestamp'])
            d['port'] = int(d['port']) if d['port'] else None
            self._events.append(Event(**d))
        self._file_path = data.get('file_path', self._file_path)

    def save_state(self, filename: Optional[str] = None) -> None:
        """Сохранение состояния в JSON."""
        filename = filename or self._state_file
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

        print(f"   Состояние сохранено в {filename}")

    def load_state(self, filename: Optional[str] = None) -> None:
        """Загрузка состояния из JSON."""
        filename = filename or self._state_file

        with open(filename, 'r', encoding='utf-8') as f:
            self.from_dict(json.load(f))

        print(f"   Состояние загружено из {filename}")