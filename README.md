# SIEM Event Analyzer

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen.svg)]()

Анализатор событий безопасности с использованием `namedtuple` для создания легких, неизменяемых структур данных.

## 📋 Описание

Проект предназначен для анализа событий безопасности (SIEM) с использованием именованных кортежей Python. Реализованы следующие функции:

- ✅ Фильтрация событий по уровню критичности
- ✅ Группировка событий по типам с использованием `Counter`
- ✅ Извлечение уникальных IP-адресов с использованием `set`
- ✅ Демонстрация неизменяемости `namedtuple`
- ✅ Генерация аналитических отчетов в JSON
- ✅ Сериализация/десериализация состояния
- ✅ Логирование
- ✅ Модульное тестирование

## 🚀 Быстрый старт

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/ваш_username/siem-event-analyzer.git
cd siem-event-analyzer

# Создание и активация виртуального окружения
python -m venv venv

# Windows
venv\Scripts\activate.bat

# Linux/Mac
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt
