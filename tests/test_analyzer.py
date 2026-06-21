"""
Модуль тестирования для EventAnalyzer.
"""

import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from collections import namedtuple
from src.event_analyzer import EventAnalyzer, Event
from src.event_generator import EventGenerator


class TestEventAnalyzer(unittest.TestCase):
    """Тесты для EventAnalyzer."""

    def setUp(self):
        """Подготовка тестовых данных."""
        # Создаем временный файл для тестов
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.events_file = self.data_dir / 'test_events.json'
        self.state_file = self.data_dir / 'test_state.json'

        # Генерируем тестовые события
        self.generator = EventGenerator(100)
        self.events = self.generator.generate_events()
        self.generator.save_to_json(str(self.events_file))

        # Создаем анализатор
        self.analyzer = EventAnalyzer(str(self.events_file))
        self.analyzer._state_file = str(self.state_file)

        # Загружаем события
        list(self.analyzer.load_events_from_file())

    def tearDown(self):
        """Очистка после тестов."""
        self.temp_dir.cleanup()

    def test_load_events_success(self):
        """Тест успешной загрузки событий."""
        self.assertEqual(len(self.analyzer.events), 100)
        self.assertIsInstance(self.analyzer.events[0], Event)

    def test_load_events_file_not_found(self):
        """Тест ошибки при отсутствии файла."""
        analyzer = EventAnalyzer('nonexistent_file.json')
        with self.assertRaises(FileNotFoundError):
            list(analyzer.load_events_from_file())

    def test_load_events_corrupted_json(self):
        """Тест ошибки при поврежденном JSON."""
        # Создаем поврежденный файл
        corrupted_file = self.data_dir / 'corrupted.json'
        corrupted_file.write_text('{corrupted: json}')

        analyzer = EventAnalyzer(str(corrupted_file))
        with self.assertRaises(json.JSONDecodeError):
            list(analyzer.load_events_from_file())

    def test_load_events_empty_file(self):
        """Тест пустого файла."""
        empty_file = self.data_dir / 'empty.json'
        empty_file.write_text('[]')

        analyzer = EventAnalyzer(str(empty_file))
        events = list(analyzer.load_events_from_file())
        self.assertEqual(len(events), 0)

    def test_filter_high_severity(self):
        """Тест фильтрации по критичности."""
        filtered = self.analyzer.filter_high_severity(threshold=5)
        # Проверяем, что все события имеют severity > 5
        for e in filtered:
            self.assertGreater(e.severity, 5)
        # Проверяем сортировку
        for i in range(len(filtered) - 1):
            self.assertLessEqual(filtered[i].timestamp, filtered[i + 1].timestamp)

    def test_filter_high_severity_boundary(self):
        """Тест граничного значения фильтрации."""
        # Создаем события с граничными значениями
        boundary_events = [
            Event(datetime.now(), '192.168.1.1', '10.0.0.1', 'TCP', 80, 'test', 5, 'Severity 5'),
            Event(datetime.now(), '192.168.1.1', '10.0.0.2', 'TCP', 80, 'test', 6, 'Severity 6'),
        ]
        self.analyzer._events = boundary_events

        filtered = self.analyzer.filter_high_severity(threshold=5)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].severity, 6)

    def test_group_by_type(self):
        """Тест группировки по типу."""
        groups = self.analyzer.group_by_type()
        self.assertIsInstance(groups, dict)
        total = sum(groups.values())
        self.assertEqual(total, len(self.analyzer.events))

    def test_get_unique_ips(self):
        """Тест получения уникальных IP."""
        unique_ips = self.analyzer.get_unique_ips()
        self.assertIsInstance(unique_ips, set)
        for e in self.analyzer.events:
            self.assertIn(e.src_ip, unique_ips)
            self.assertIn(e.dst_ip, unique_ips)

    def test_demonstrate_immutability(self):
        """Тест неизменяемости namedtuple."""
        try:
            self.analyzer.demonstrate_immutability()
            # Если не было исключения, тест провален
            self.fail("Expected AttributeError")
        except AttributeError:
            pass  # Ожидаемое поведение

    def test_to_dict(self):
        """Тест сериализации в словарь."""
        state = self.analyzer.to_dict()
        self.assertIn('events', state)
        self.assertIn('file_path', state)
        self.assertIn('event_count', state)
        self.assertEqual(state['event_count'], len(self.analyzer.events))

    def test_from_dict(self):
        """Тест восстановления из словаря."""
        state = self.analyzer.to_dict()

        new_analyzer = EventAnalyzer('test.json')
        new_analyzer.from_dict(state)

        self.assertEqual(len(new_analyzer.events), len(self.analyzer.events))
        self.assertEqual(new_analyzer._file_path, self.analyzer._file_path)

    def test_save_and_load_state(self):
        """Тест сохранения и загрузки состояния."""
        # Сохраняем состояние
        self.analyzer.save_state()
        self.assertTrue(self.state_file.exists())

        # Создаем новый анализатор и загружаем состояние
        new_analyzer = EventAnalyzer(str(self.events_file))
        new_analyzer._state_file = str(self.state_file)
        new_analyzer.load_state()

        self.assertEqual(len(new_analyzer.events), len(self.analyzer.events))

    def test_generate_report(self):
        """Тест генерации отчета."""
        report_file = self.data_dir / 'report.json'
        self.analyzer.generate_report(str(report_file))

        self.assertTrue(report_file.exists())

        with open(report_file, 'r', encoding='utf-8') as f:
            report = json.load(f)

        self.assertIn('total_events', report)
        self.assertIn('event_types', report)
        self.assertIn('unique_ips', report)
        self.assertEqual(report['total_events'], len(self.analyzer.events))


if __name__ == '__main__':
    unittest.main()