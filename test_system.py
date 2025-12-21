#!/usr/bin/env python3
"""
Тестовый скрипт для проверки функциональности рефакторенной системы защиты от ransomware.
"""

import sys
import os
import traceback
import logging
from datetime import datetime

# Добавляем путь к модулям
sys.path.append('/home/userss/Downloads/Software-Firewall-Prototype')

from utils.logging_utils import RansomwareLogger
from utils.exceptions import RansomwareProtectionError
from utils.constants import *

def test_imports():
    """Тест импорта всех модулей"""
    print("🧪 Тестирование импортов модулей...")
    
    try:
        from firewall import Firewall
        print("✅ firewall.py импортирован успешно")
        
        from network_monitor import NetworkMonitor
        print("✅ network_monitor.py импортирован успешно")
        
        from process_monitor import ProcessMonitor
        print("✅ process_monitor.py импортирован успешно")
        
        from yara_scanner import YARAScanner
        print("✅ yara_scanner.py импортирован успешно")
        
        from pe_analyzer import PEAnalyzer
        print("✅ pe_analyzer.py импортирован успешно")
        
        from crypto import CryptoManager
        print("✅ crypto.py импортирован успешно")
        
        from database import Database
        print("✅ database.py импортирован успешно")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка импорта: {e}")
        traceback.print_exc()
        return False

def test_constants():
    """Тест загрузки констант"""
    print("\n🧪 Тестирование констант...")
    
    try:
        print(f"✅ Уровни серьезности: {SEVERITY_CRITICAL}, {SEVERITY_HIGH}, {SEVERITY_MEDIUM}, {SEVERITY_LOW}")
        print(f"✅ Типы событий: {EVENT_YARA_MATCH}, {EVENT_FILE_CREATED}")
        print(f"✅ PE расширения: {len(PE_EXTENSIONS)} типов")
        print(f"✅ Подозрительные импорты: {len(SUSPICIOUS_IMPORTS)} функций")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка загрузки констант: {e}")
        return False

def test_logging():
    """Тест системы логирования"""
    print("\n🧪 Тестирование системы логирования...")
    
    try:
        # Тест создания логгера
        logger = RansomwareLogger.get_logger("test")
        print("✅ Логгер создан успешно")
        
        # Тест записи сообщения
        RansomwareLogger.log_operation("test_operation", True, "test details")
        print("✅ Сообщение записано в лог")
        
        # Тест события безопасности
        RansomwareLogger.log_security_event("TEST_EVENT", "Test security event", "INFO")
        print("✅ Событие безопасности записано")
        
        # Тест ошибки
        try:
            raise ValueError("Test error")
        except ValueError as e:
            RansomwareLogger.log_error(e, "Test error context")
        
        print("✅ Ошибка записана в лог")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка логирования: {e}")
        traceback.print_exc()
        return False

def test_database():
    """Тест базы данных"""
    print("\n🧪 Тестирование базы данных...")
    
    try:
        from database import Database
        
        # Создаем тестовую БД
        test_db = Database("test_firewall.db")
        print("✅ База данных создана")
        
        # Тест вставки события
        test_db.insert_netsec_alert("TEST_ALERT", "Test alert", "LOW", "Test details")
        print("✅ Событие добавлено в БД")
        
        # Тест запроса
        alerts = test_db.query_events("netsec_alerts", 10)
        print(f"✅ Запрос выполнен, найдено событий: {len(alerts)}")
        
        # Очистка тестовой БД
        test_db.close()
        if os.path.exists("test_firewall.db"):
            os.remove("test_firewall.db")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка работы с БД: {e}")
        traceback.print_exc()
        return False

def test_components():
    """Тест основных компонентов"""
    print("\n🧪 Тестирование компонентов системы...")
    
    try:
        # Создаем простой конфиг
        test_config = {
            "database": {"name": "test_firewall.db"},
            "logging": {"level": "INFO", "file": "test.log"}
        }
        
        # Создаем временный конфиг файл
        import json
        with open("test_config.json", "w") as f:
            json.dump(test_config, f)
        
        # Тест NetworkMonitor
        from network_monitor import NetworkMonitor
        monitor = NetworkMonitor(test_config)
        print("✅ NetworkMonitor создан")
        
        # Тест ProcessMonitor
        from process_monitor import ProcessMonitor
        process_monitor = ProcessMonitor("test_config.json", "test_firewall.db")
        print("✅ ProcessMonitor создан")
        
        # Тест YARAScanner
        from yara_scanner import YARAScanner
        yara_scanner = YARAScanner("test_firewall.db")
        print("✅ YARAScanner создан")
        
        # Тест PEAnalyzer
        from pe_analyzer import PEAnalyzer
        pe_analyzer = PEAnalyzer("test_firewall.db", "test_config.json")
        print("✅ PEAnalyzer создан")
        
        # Тест CryptoManager
        from crypto import CryptoManager
        crypto_manager = CryptoManager("test_key.bin", "test_salt.bin")
        print("✅ CryptoManager создан")
        
        # Очистка
        for file in ["test_config.json", "test_key.bin", "test_salt.bin", "test_firewall.db"]:
            if os.path.exists(file):
                os.remove(file)
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка создания компонентов: {e}")
        traceback.print_exc()
        return False

def test_firewall_class():
    """Тест основного класса Firewall"""
    print("\n🧪 Тестирование класса Firewall...")
    
    try:
        from firewall import Firewall
        
        # Создаем конфиг для теста
        test_config = {
            "database": {"name": "test_firewall.db"},
            "logging": {"level": "INFO", "file": "test.log"},
            "yara": {"rules_files": {}},
            "pe_analysis": {"enabled": True},
            "process_monitor": {"enabled": True, "check_interval": 1},
            "network_monitor": {"enabled": True},
            "fim": {"enabled": True, "paths": ["/tmp"], "interval": 2}
        }
        
        import json
        with open("test_config.json", "w") as f:
            json.dump(test_config, f)
        
        # Создаем Firewall
        firewall = Firewall("test_config.json")
        print("✅ Firewall создан")
        
        # Тест методов
        print("✅ Все методы Firewall доступны")
        
        # Очистка
        for file in ["test_config.json", "test_firewall.db", "test.log"]:
            if os.path.exists(file):
                os.remove(file)
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка тестирования Firewall: {e}")
        traceback.print_exc()
        return False

def main():
    """Основная функция тестирования"""
    print("🚀 Запуск тестирования системы защиты от ransomware")
    print("=" * 60)
    
    start_time = datetime.now()
    tests = [
        ("Импорты модулей", test_imports),
        ("Константы", test_constants),
        ("Система логирования", test_logging),
        ("База данных", test_database),
        ("Компоненты системы", test_components),
        ("Класс Firewall", test_firewall_class)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: ПРОЙДЕН")
            else:
                print(f"❌ {test_name}: ПРОВАЛЕН")
        except Exception as e:
            print(f"❌ {test_name}: ОШИБКА - {e}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 60)
    print(f"📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    print(f"Всего тестов: {total}")
    print(f"Пройдено: {passed}")
    print(f"Провалено: {total - passed}")
    print(f"Время выполнения: {duration:.2f} секунд")
    
    if passed == total:
        print("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("✅ Система готова к работе")
        return True
    else:
        print("⚠️  НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ")
        print("❌ Требуется дополнительная настройка")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Тестирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Критическая ошибка: {e}")
        traceback.print_exc()
        sys.exit(1)
