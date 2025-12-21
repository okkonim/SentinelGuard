# Команды для демонстрации работоспособности всех модулей системы защиты

## 🎯 Основные команды для тестирования системы

### 1. Запуск полной демонстрации всех модулей
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 demo_all_modules.py
```

**Результат:** Автоматическое тестирование всех 7 основных модулей с отчетом о результатах

### 2. Интерактивное тестирование межсетевого экрана
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 firewall.py interactive
```

**Доступные пункты меню:**
- `1` - Запустить все модули
- `2` - Запустить гибридный сетевой сниффер  
- `3` - Запустить модуль FIM
- `4` - Запустить модуль мониторинга процессов
- `5` - Запустить модуль сетевого мониторинга
- `6` - Запустить систему защиты от ransomware
- `7` - Просмотр логов
- `8` - Перезагрузка правил
- `9` - Сканирование сетевых угроз
- `10` - Создание базовой линии
- `11` - Сравнение с базовой линией
- `12` - Ручное YARA сканирование
- `13` - Просмотр YARA правил
- `14` - PE анализ файла
- `15` - Просмотр PE отчетов
- `0` - Выход

### 3. Тестирование системы защиты от ransomware
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 ransomware_protection_system.py start
```

**Для остановки:** Нажмите `Ctrl+C`

### 4. Создание тестовых файлов для демонстрации
```bash
cd /home/userss/Downloads/Software-Firewall-Prototype
python3 ransomware_protection_system.py test --dir ./test_files_demo
```

### 5. Просмотр статистики событий
```bash
# Просмотр событий FIM
python3 firewall.py logs --table fim_events --limit 10

# Просмотр событий процессов  
python3 firewall.py logs --table process_events --limit 10

# Просмотр событий сетевой безопасности
python3 firewall.py logs --table netsec_alerts --limit 10

# Просмотр событий YARA
python3 firewall.py logs --table yara_events --limit 10
```

### 6. Ручное сканирование файлов
```bash
# YARA сканирование
python3 firewall.py scan --path /etc/passwd

# PE анализ файла
python3 firewall.py pe-analyze --path /bin/ls

# Просмотр PE отчетов
python3 firewall.py pe-reports --limit 5
```

### 7. Проверка конфигурации и правил
```bash
# Просмотр загруженных YARA правил
python3 firewall.py rules

# Перезагрузка конфигурации
python3 firewall.py reload
```

## 🔍 Отображение модулей согласно техническому заданию

### Интеграционные модули:
```bash
# Модуль интеграции и автоматического реагирования
python3 ransomware_protection_system.py start &

# Интеграция Firewall с FIM
python3 firewall.py interactive
# Выберите пункт 1 (Запустить все модули)

# Интеграция Firewall с мониторингом процессов  
python3 firewall.py interactive
# Выберите пункт 1 (Запустить все модули)
```

### Специализированные модули:
```bash
# YARA-сканер с управлением правилами
python3 firewall.py rules
python3 firewall.py scan --path ./test_files_demo

# Анализ PE-файлов с выявлением аномалий
python3 firewall.py pe-analyze --path /bin/bash
python3 firewall.py pe-reports --limit 10
```

### Мониторинговые модули:
```bash
# FIM мониторинг
python3 firewall.py interactive
# Выберите пункт 3 (Запустить модуль FIM)

# Мониторинг процессов
python3 firewall.py interactive  
# Выберите пункт 4 (Запустить модуль мониторинга процессов)

# Сетевой мониторинг
python3 firewall.py interactive
# Выберите пункт 5 (Запустить модуль сетевого мониторинга)
```

## 📊 Краткий отчет о функциональности

**Работающие модули (из демонстрации):**
- ✅ **Firewall Module** - Центральная система управления
- ✅ **YARA Scanner Module** - Сигнатурное обнаружение угроз
- ✅ **PE Analyzer Module** - Статический анализ исполняемых файлов  
- ✅ **Anomaly Detection Module** - Выявление аномалий в PE-файлах
- ✅ **Integration System** - Система интеграции и корреляции событий

**Требуют доработки:**
- ⚠️ **FIM Module** - Модуль контроля целостности файлов
- ⚠️ **Process Monitor Module** - Модуль мониторинга процессов

## 🎯 Команды для получения логов системы
```bash
# Просмотр логов в реальном времени
tail -f ransomware_protection.log

# Просмотр последних 50 строк логов
tail -50 ransomware_protection.log

# Поиск ошибок в логах
grep -i error ransomware_protection.log
```

## 🚀 Быстрая демонстрация (рекомендуемая последовательность)
```bash
# 1. Запуск полной демонстрации
python3 demo_all_modules.py

# 2. Интерактивное тестирование  
python3 firewall.py interactive
# Выберите пункты: 6, 12, 14, 15

# 3. Проверка логов
python3 firewall.py logs --table netsec_alerts --limit 5
```

**Общий результат демонстрации:** 5 из 7 модулей работают корректно (71.4% успешности)
