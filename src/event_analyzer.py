"""
Модуль для анализа событий безопасности с использованием namedtuple.
"""

import json
import logging
import os
from collections import namedtuple, Counter
from datetime import datetime
from typing import List, Set, Dict, Any, Generator, Optional
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Создаем именованный кортеж для событий
Event = namedtuple('Event', ['timestamp', 'src_ip', 'dst_ip', 'protocol',
                            'port', 'event_type', 'severity', 'description'])


class EventAnalyzer:
    """
    Анализатор событий безопасности.

    Attributes:
        _events (List[Event]): Список событий.
        _file_path (str): Путь к файлу с данными.
        _state_file (str): Путь к файлу состояния.
        _report_file (str): Путь к файлу отчета.
    """

    def __init__(self, file_path: str = 'data/events.json'):
        """
        Инициализация анализатора.

        Args:
            file_path: Путь к JSON файлу с событиями.
        """
        self._events: List[Event] = []

        # Определяем корневую директорию проекта (где находится src)
        # Получаем путь к директории, где находится этот файл (src)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Поднимаемся на один уровень вверх (в корень проекта)
        project_root = os.path.dirname(current_dir)

        # Создаем папку data в корне проекта
        self._data_dir = os.path.join(project_root, 'data')
        os.makedirs(self._data_dir, exist_ok=True)

        # Если передан относительный путь, преобразуем его в абсолютный
        if file_path == 'data/events.json' or not os.path.isabs(file_path):
            self._file_path = os.path.join(self._data_dir, 'events.json')
        else:
            self._file_path = file_path

        self._state_file = os.path.join(self._data_dir, 'state.json')
        self._report_file = os.path.join(self._data_dir, 'report.json')

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Инициализация анализатора с файлом: {self._file_path}")
        self.logger.info(f"Директория данных: {self._data_dir}")

    @property
    def events(self) -> List[Event]:
        """Получение списка событий."""
        return self._events

    @events.setter
    def events(self, value: List[Event]) -> None:
        """Установка списка событий (скрытое поле)."""
        self._events = value

    def load_events_from_file(self) -> Generator[Event, None, None]:
        """
        Загрузка событий из JSON файла с использованием генератора.

        Returns:
            Generator[Event, None, None]: Генератор событий.

        Raises:
            FileNotFoundError: Если файл не найден.
            json.JSONDecodeError: Если файл поврежден.
        """
        self.logger.info(f"Загрузка событий из файла: {self._file_path}")

        try:
            # Проверяем существование файла
            if not os.path.exists(self._file_path):
                self.logger.warning(f"Файл {self._file_path} не найден")
                raise FileNotFoundError(f"Файл не найден: {self._file_path}")

            with open(self._file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                if not isinstance(data, list):
                    raise ValueError("Файл должен содержать массив событий")

                if len(data) == 0:
                    self.logger.warning("Файл пуст")
                    return

                for item in data:
                    # Преобразование строки timestamp в datetime
                    item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                    # Преобразование порта
                    item['port'] = int(item['port']) if item['port'] is not None else None

                    event = Event(**item)
                    self._events.append(event)
                    self.logger.debug(f"Загружено событие: {event}")
                    yield event

        except FileNotFoundError as e:
            self.logger.error(f"Файл не найден: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Ошибка парсинга JSON: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Неизвестная ошибка: {e}")
            raise

    def filter_high_severity(self, threshold: int = 5) -> List[Event]:
        """
        Фильтрация событий с уровнем критичности выше порога.

        Args:
            threshold: Порог критичности.

        Returns:
            List[Event]: Отфильтрованные события, отсортированные по времени.
        """
        self.logger.info(f"Фильтрация событий с severity > {threshold}")

        filtered = [e for e in self._events if e.severity > threshold]
        sorted_events = sorted(filtered, key=lambda e: e.timestamp)

        self.logger.debug(f"Найдено {len(sorted_events)} событий с severity > {threshold}")
        return sorted_events

    def group_by_type(self) -> Dict[str, int]:
        """
        Группировка событий по типу.

        Returns:
            Dict[str, int]: Словарь с количеством событий каждого типа.
        """
        self.logger.info("Группировка событий по типу")

        counter = Counter(e.event_type for e in self._events)
        result = dict(counter)

        self.logger.debug(f"Найдено {len(result)} уникальных типов событий")
        return result

    def get_unique_ips(self) -> Set[str]:
        """
        Извлечение уникальных IP-адресов.

        Returns:
            Set[str]: Множество уникальных IP-адресов.
        """
        self.logger.info("Извлечение уникальных IP-адресов")

        unique_ips = set()
        for e in self._events:
            unique_ips.add(e.src_ip)
            unique_ips.add(e.dst_ip)

        self.logger.debug(f"Найдено {len(unique_ips)} уникальных IP-адресов")
        return unique_ips

    def demonstrate_immutability(self) -> None:
        """
        Демонстрация неизменяемости namedtuple.
        """
        self.logger.info("Демонстрация неизменяемости namedtuple")

        if not self._events:
            self.logger.warning("Нет событий для демонстрации")
            print("   Нет событий для демонстрации")
            return

        try:
            e = self._events[0]
            self.logger.info(f"Попытка изменить поле severity события: {e}")
            e.severity = 10  # Это вызовет ошибку
        except AttributeError as err:
            self.logger.info(f"Ошибка при попытке изменить поле namedtuple: {err}")
            print(f"   ✓ Ошибка при попытке изменить поле namedtuple: {err}")
            print("   Демонстрация успешна: поля namedtuple нельзя изменить")

    def generate_report(self, filename: Optional[str] = None) -> None:
        """
        Генерация аналитического отчета в формате JSON.

        Формат отчета:
        {
            "generated_at": "2024-06-01T12:00:00",
            "total_events": 1000,
            "high_severity_events": 123,
            "event_types": {"login_failure": 150, ...},
            "unique_ips": ["192.168.1.1", ...],
            "immutability_demo": "Namedtuple fields cannot be modified"
        }

        Args:
            filename: Путь к файлу для сохранения отчета (по умолчанию data/report.json).
        """
        if filename is None:
            filename = self._report_file

        self.logger.info(f"Генерация отчета в файл: {filename}")

        # Создаем директорию, если её нет
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

        self.logger.info(f"Отчет сохранен в {filename}")
        print(f"   Отчет сохранен в {filename}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация состояния объекта в словарь.

        Returns:
            Dict[str, Any]: Словарь с состоянием объекта.
        """
        self.logger.debug("Сериализация состояния в словарь")

        events_dict = []
        for e in self._events:
            event_dict = e._asdict()
            event_dict['timestamp'] = event_dict['timestamp'].isoformat()
            event_dict['port'] = str(event_dict['port']) if event_dict['port'] is not None else None
            events_dict.append(event_dict)

        return {
            'events': events_dict,
            'file_path': self._file_path,
            'event_count': len(self._events),
            'saved_at': datetime.now().isoformat()
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        """
        Восстановление состояния объекта из словаря.

        Args:
            data: Словарь с состоянием объекта.
        """
        self.logger.info("Восстановление состояния из словаря")

        self._events = []
        for event_dict in data.get('events', []):
            event_dict['timestamp'] = datetime.fromisoformat(event_dict['timestamp'])
            event_dict['port'] = int(event_dict['port']) if event_dict['port'] is not None else None
            self._events.append(Event(**event_dict))

        self._file_path = data.get('file_path', self._file_path)

        self.logger.info(f"Восстановлено {len(self._events)} событий")

    def save_state(self, filename: Optional[str] = None) -> None:
        """
        Сохранение полного состояния объекта в JSON файл.

        Args:
            filename: Путь к файлу для сохранения состояния.
        """
        if filename is None:
            filename = self._state_file

        self.logger.info(f"Сохранение состояния в файл: {filename}")

        # Создаем директорию, если её нет
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        state = self.to_dict()
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

        self.logger.info(f"Состояние сохранено в {filename}")
        print(f"   Состояние сохранено в {filename}")

    def load_state(self, filename: Optional[str] = None) -> None:
        """
        Загрузка полного состояния из JSON файла.

        Args:
            filename: Путь к файлу для загрузки состояния.
        """
        if filename is None:
            filename = self._state_file

        self.logger.info(f"Загрузка состояния из файла: {filename}")

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.from_dict(data)
                self.logger.info(f"Состояние загружено из {filename}")
                print(f"   Состояние загружено из {filename}")
        except FileNotFoundError as e:
            self.logger.error(f"Файл состояния не найден: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Ошибка парсинга JSON состояния: {e}")
            raise