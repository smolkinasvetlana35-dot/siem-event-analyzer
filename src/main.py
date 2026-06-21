"""
Главный модуль для запуска приложения.
"""

import sys
import os
from pathlib import Path

# Добавляем путь к src в sys.path для импорта модулей
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from event_generator import EventGenerator
from event_analyzer import EventAnalyzer


def main():
    """Главная функция приложения."""
    print("=== SIEM Event Analyzer ===\n")

    # Определяем корневую директорию проекта
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    data_dir = os.path.join(project_root, 'data')
    os.makedirs(data_dir, exist_ok=True)

    events_file = os.path.join(data_dir, 'events.json')

    # Если файла нет, генерируем данные
    if not os.path.exists(events_file):
        print("Генерация тестовых событий...")
        generator = EventGenerator(1000)
        events = generator.generate_events()
        generator.save_to_json(events_file)
        print(f"Сгенерировано {len(events)} событий\n")
    else:
        print(f"Загрузка существующих событий из {events_file}\n")

    # Создание анализатора
    analyzer = EventAnalyzer(events_file)

    try:
        # Загрузка событий
        print("Загрузка событий...")
        event_generator = analyzer.load_events_from_file()
        event_count = sum(1 for _ in event_generator)
        print(f"Загружено {event_count} событий\n")

        # 1. Фильтрация и сортировка
        print("1. События с критичностью > 5 (отсортированы по времени):")
        filtered = analyzer.filter_high_severity()
        if filtered:
            for i, e in enumerate(filtered[:5], 1):
                print(f"   {i}. {e.timestamp} | {e.event_type} | Severity: {e.severity} | {e.description[:50]}...")
            if len(filtered) > 5:
                print(f"   ... и еще {len(filtered) - 5} событий")
        else:
            print("   Нет событий с критичностью > 5")
        print()

        # 2. Группировка по типу
        print("2. Количество событий по типам:")
        groups = analyzer.group_by_type()
        if groups:
            for event_type, count in sorted(groups.items(), key=lambda x: -x[1])[:5]:
                print(f"   {event_type}: {count}")
            if len(groups) > 5:
                print(f"   ... и еще {len(groups) - 5} типов")
        else:
            print("   Нет событий для группировки")
        print()

        # 3. Уникальные IP
        print("3. Уникальные IP-адреса:")
        unique_ips = analyzer.get_unique_ips()
        print(f"   Всего уникальных IP: {len(unique_ips)}")
        if unique_ips:
            for ip in sorted(unique_ips)[:10]:
                print(f"   {ip}")
            if len(unique_ips) > 10:
                print(f"   ... и еще {len(unique_ips) - 10} IP")
        else:
            print("   Нет IP-адресов")
        print()

        # 4. Демонстрация неизменяемости
        print("4. Демонстрация неизменяемости namedtuple:")
        if analyzer.events:
            analyzer.demonstrate_immutability()
        else:
            print("   Нет событий для демонстрации")
        print()

        # 5. Генерация отчета
        print("5. Генерация отчета...")
        analyzer.generate_report()

        # 6. Сохранение состояния
        print("\n6. Сохранение состояния...")
        analyzer.save_state()

        # 7. Загрузка состояния (демонстрация)
        print("\n7. Загрузка состояния...")
        new_analyzer = EventAnalyzer(events_file)
        new_analyzer.load_state()
        print(f"   Загружено {len(new_analyzer.events)} событий из состояния")

        print("\n=== Анализ завершен ===")

    except FileNotFoundError as e:
        print(f"Ошибка: Файл не найден - {e}")
        print("Пожалуйста, сначала сгенерируйте данные с помощью EventGenerator")
    except Exception as e:
        print(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()