import unittest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from src.event_analyzer import EventAnalyzer, Event
from src.event_generator import EventGenerator


class TestEventAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.events_file = self.data_dir / 'test_events.json'
        self.state_file = self.data_dir / 'test_state.json'

        generator = EventGenerator(100)
        generator.generate_events()
        generator.save_to_json(str(self.events_file))

        self.analyzer = EventAnalyzer(str(self.events_file))
        self.analyzer._state_file = str(self.state_file)
        list(self.analyzer.load_events_from_file())

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_events_success(self):
        """Тест успешной загрузки событий."""
        self.assertEqual(len(self.analyzer.events), 100)
        self.assertIsInstance(self.analyzer.events[0], Event)

    def test_load_events_file_not_found(self):
        """Тест ошибки при отсутствии файла."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_file = Path(tmpdir) / 'nonexistent.json'
            analyzer = EventAnalyzer(str(fake_file))
            with self.assertRaises(FileNotFoundError):
                list(analyzer.load_events_from_file())

    def test_load_events_corrupted_json(self):
        """Тест ошибки при поврежденном JSON."""
        corrupted = self.data_dir / 'corrupted.json'
        corrupted.write_text('{corrupted: json}')

        analyzer = EventAnalyzer(str(corrupted))
        with self.assertRaises(json.JSONDecodeError):
            list(analyzer.load_events_from_file())

    def test_load_events_empty_file(self):
        """Тест пустого файла."""
        empty = self.data_dir / 'empty.json'
        empty.write_text('[]')

        analyzer = EventAnalyzer(str(empty))
        self.assertEqual(len(list(analyzer.load_events_from_file())), 0)

    def test_filter_high_severity(self):
        """Тест фильтрации по критичности."""
        filtered = self.analyzer.filter_high_severity(5)

        for e in filtered:
            self.assertGreater(e.severity, 5)

        for i in range(len(filtered) - 1):
            self.assertLessEqual(filtered[i].timestamp, filtered[i+1].timestamp)

    def test_filter_high_severity_boundary(self):
        """Тест граничного значения фильтрации."""
        now = datetime.now()
        self.analyzer._events = [
            Event(now, '1.1.1.1', '2.2.2.2', 'TCP', 80, 'test', 5, 'Severity 5'),
            Event(now, '1.1.1.1', '2.2.2.2', 'TCP', 80, 'test', 6, 'Severity 6'),
        ]

        filtered = self.analyzer.filter_high_severity(5)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].severity, 6)

    def test_group_by_type(self):
        """Тест группировки по типу."""
        groups = self.analyzer.group_by_type()
        self.assertIsInstance(groups, dict)
        self.assertEqual(sum(groups.values()), len(self.analyzer.events))

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
        except Exception as e:
            self.fail(f"Метод не должен выбрасывать исключение, но выбросил: {e}")

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
        self.analyzer.save_state()
        self.assertTrue(self.state_file.exists())

        new_analyzer = EventAnalyzer(str(self.events_file))
        new_analyzer._state_file = str(self.state_file)
        new_analyzer.load_state()

        self.assertEqual(len(new_analyzer.events), len(self.analyzer.events))

    def test_generate_report(self):
        """Тест генерации отчета."""
        report_file = self.data_dir / 'report.json'
        self.analyzer.generate_report(str(report_file))
        self.assertTrue(report_file.exists())

        with open(report_file) as f:
            report = json.load(f)

        self.assertIn('total_events', report)
        self.assertIn('event_types', report)
        self.assertIn('unique_ips', report)
        self.assertEqual(report['total_events'], len(self.analyzer.events))


if __name__ == '__main__':
    unittest.main()