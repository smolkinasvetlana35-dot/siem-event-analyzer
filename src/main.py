"""
Главный модуль для запуска приложения.
"""

import os
import sys
from event_generator import EventGenerator
from event_analyzer import EventAnalyzer


def main():
    """Главная функция приложения."""
    print("=== SIEM Event Analyzer ===\n")

    # Путь к файлу с данными
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    os.makedirs(data_dir, exist_ok=True)
    events_file = os.path.join(data_dir, 'events.json')

    # Генерация данных при отсутствии файла
    if not os.path.exists(events_file):
        print("Генерация тестовых событий...")
        generator = EventGenerator(1000)
        events = generator.generate_events()
        generator.save_to_json(events_file)
        print(f"Сгенерировано {len(events)} событий\n")

    # Анализ данных
    analyzer = EventAnalyzer(events_file)

    try:
        # Загрузка событий
        print("Загрузка событий...")
        event_count = sum(1 for _ in analyzer.load_events_from_file())
        print(f"Загружено {event_count} событий\n")

        # 1. Фильтрация
        print("1. События с критичностью > 5:")
        filtered = analyzer.filter_high_severity()
        for i, e in enumerate(filtered[:5], 1):
            print(f"   {i}. {e.timestamp} | {e.event_type} | Severity: {e.severity}")
        print(f"   ... всего {len(filtered)} событий\n")

        # 2. Группировка
        print("2. Топ-5 типов событий:")
        groups = analyzer.group_by_type()
        for event_type, count in sorted(groups.items(), key=lambda x: -x[1])[:5]:
            print(f"   {event_type}: {count}")
        print()

        # 3. Уникальные IP
        print("3. Уникальные IP-адреса:")
        unique_ips = analyzer.get_unique_ips()
        print(f"   Всего: {len(unique_ips)}")
        for ip in sorted(unique_ips)[:10]:
            print(f"   {ip}")
        print()

        # 4. Неизменяемость namedtuple
        print("4. Демонстрация неизменяемости:")
        analyzer.demonstrate_immutability()
        print()

        # 5. Отчет и состояние
        print("5. Генерация отчета...")
        analyzer.generate_report()

        print("6. Сохранение состояния...")
        analyzer.save_state()

        print("\n=== Анализ завершен ===")

    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()