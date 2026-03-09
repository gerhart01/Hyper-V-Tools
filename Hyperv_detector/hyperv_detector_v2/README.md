# Hyper-V Detector

Комплексный инструмент для обнаружения виртуализации Microsoft Hyper-V в Windows.

## Структура проекта

```
hyperv_detector/
├── hyperv_detector.sln          # Solution файл Visual Studio
├── hyperv_detector.vcxproj      # Проект UserMode приложения
├── hyperv_driver.vcxproj        # Проект KernelMode драйвера
├── src/
│   ├── common/                  # Общие заголовки
│   │   ├── common.h
│   │   └── shared_structs.h
│   ├── user_mode/               # UserMode код (25 методов детекции)
│   │   ├── hyperv_detector.h
│   │   ├── hyperv_detector_new.h
│   │   ├── main.c               # Оригинальный main
│   │   ├── main_new.c           # Расширенный main с уровнями детекции
│   │   ├── bios_checks.c
│   │   ├── cpuid_checks.c
│   │   ├── device_checks.c
│   │   ├── file_checks.c
│   │   ├── process_checks.c
│   │   ├── registry_checks.c
│   │   ├── service_checks.c
│   │   ├── wmi_checks.c         # NEW: WMI проверки
│   │   ├── mac_checks.c         # NEW: MAC-адреса
│   │   ├── firmware_checks.c    # NEW: SMBIOS/ACPI
│   │   ├── timing_checks.c      # NEW: Анализ тайминга
│   │   ├── perfcounter_checks.c # NEW: Счётчики производительности
│   │   ├── eventlog_checks.c    # NEW: Журналы событий
│   │   ├── security_checks.c    # NEW: VBS/HVCI/Credential Guard
│   │   ├── descriptor_checks.c  # NEW: IDT/GDT анализ
│   │   ├── features_checks.c    # NEW: Компоненты Windows
│   │   ├── storage_checks.c     # NEW: Анализ дисков
│   │   ├── env_checks.c         # NEW: Переменные окружения
│   │   ├── network_checks.c     # NEW: Сетевая топология
│   │   ├── dll_checks.c         # NEW: DLL анализ
│   │   └── root_partition_checks.c # NEW: Root/Child partition
│   └── kernel_mode/             # KernelMode драйвер
│       ├── hyperv_driver.h
│       ├── hyperv_driver.c
│       ├── hypercall_checks.c
│       ├── hypercall_perform.c
│       └── ASM64.asm
```

## Флаги обнаружения

| Флаг | Значение | Метод |
|------|----------|-------|
| HYPERV_DETECTED_CPUID | 0x00000001 | CPUID |
| HYPERV_DETECTED_REGISTRY | 0x00000002 | Реестр |
| HYPERV_DETECTED_FILES | 0x00000004 | Файлы |
| HYPERV_DETECTED_SERVICES | 0x00000008 | Службы |
| HYPERV_DETECTED_DEVICES | 0x00000010 | Устройства |
| HYPERV_DETECTED_BIOS | 0x00000020 | BIOS |
| HYPERV_DETECTED_PROCESSES | 0x00000040 | Процессы |
| HYPERV_DETECTED_HYPERCALL | 0x00000080 | Hypercall |
| HYPERV_DETECTED_OBJECTS | 0x00000100 | Объекты Windows |
| HYPERV_DETECTED_NESTED | 0x00000200 | Вложенная виртуализация |
| HYPERV_DETECTED_SANDBOX | 0x00000400 | Windows Sandbox |
| HYPERV_DETECTED_DOCKER | 0x00000800 | Docker/Контейнеры |
| HYPERV_DETECTED_REMOVED | 0x00001000 | Остатки удалённого Hyper-V |
| HYPERV_DETECTED_WMI | 0x00002000 | WMI |
| HYPERV_DETECTED_MAC | 0x00004000 | MAC-адреса |
| HYPERV_DETECTED_FIRMWARE | 0x00008000 | Firmware/SMBIOS |
| HYPERV_DETECTED_TIMING | 0x00010000 | Анализ тайминга |
| HYPERV_DETECTED_PERFCOUNTER | 0x00020000 | Счётчики производительности |
| HYPERV_DETECTED_EVENTLOG | 0x00040000 | Журналы событий |
| HYPERV_DETECTED_SECURITY | 0x00080000 | Функции безопасности |
| HYPERV_DETECTED_DESCRIPTOR | 0x00100000 | Дескрипторные таблицы |
| HYPERV_DETECTED_FEATURES | 0x00200000 | Компоненты Windows |
| HYPERV_DETECTED_STORAGE | 0x00400000 | Хранилище |
| HYPERV_DETECTED_ENV | 0x00800000 | Окружение |
| HYPERV_DETECTED_NETWORK | 0x01000000 | Сеть |
| HYPERV_DETECTED_DLL | 0x02000000 | DLL-библиотеки |
| HYPERV_DETECTED_ROOT_PART | 0x04000000 | Root Partition |

## Root Partition Detection

Особая функция для определения типа раздела Hyper-V:
- **Root Partition** - хост с включённым Hyper-V/VBS (без виртуализации самого хоста)
- **Child Partition** - гостевая виртуальная машина

### Методы определения Root Partition

1. **CPUID 0x40000003 (HV_PARTITION_PRIVILEGE_MASK)**
   - EBX bit 0: CreatePartitions - только root partition
   - EBX bit 12: CpuManagement - только root partition

2. **CPUID 0x40000007 (CPU Management Features)**
   - EAX bit 31: ReservedIdentityBit - индикатор root partition

3. **Performance Counters**
   - "Hyper-V Hypervisor Root Virtual Processor" - существует только на root

4. **WMI System Model**
   - Guest VM: "Virtual Machine"
   - Root partition: реальная модель оборудования

5. **VMBus vs VMBusr**
   - `vmbus.sys` / `\Device\VmBus` - присутствует в guest VM
   - `vmbusr.sys` / `\Device\VmBusr` - присутствует только в root partition
   - Это надёжный индикатор: VMBusr = root, VMBus без VMBusr = guest

### Hypercalls только для Root Partition

| Код | Hypercall | Привилегия |
|-----|-----------|------------|
| 0x0040 | HvCallCreatePartition | CreatePartitions |
| 0x0041 | HvCallInitializePartition | CreatePartitions |
| 0x0048 | HvCallDepositMemory | AccessMemoryPool |
| 0x005E | HvCallCreateVp | CpuManagement |
| 0x0099 | HvCallStartVirtualProcessor | CpuManagement |

Child partition получает `HV_STATUS_ACCESS_DENIED (0x0006)` при попытке вызова.

## Добавленные библиотеки

Для новых модулей требуются дополнительные библиотеки:
- `ole32.lib` - COM инициализация
- `oleaut32.lib` - OLE Automation
- `wbemuuid.lib` - WMI
- `pdh.lib` - Performance Data Helper
- `wevtapi.lib` - Windows Event Log API
- `iphlpapi.lib` - IP Helper API
- `ws2_32.lib` - Winsock
- `ntdll.lib` - NT API (для NtQuerySystemInformation)

## Сборка

1. Откройте `hyperv_detector.sln` в Visual Studio 2022
2. Выберите конфигурацию (Debug/Release) и платформу (x64)
3. Соберите solution (Ctrl+Shift+B)

Для сборки драйвера требуется Windows Driver Kit (WDK).

## Использование

```
hyperv_detector.exe [опции]

Опции:
  --fast      Быстрая проверка (CPUID, реестр, файлы)
  --thorough  Тщательная проверка
  --full      Полная проверка (включая timing и descriptor)
  --json      Вывод в формате JSON
  --quiet     Минимальный вывод
  --details   Подробный вывод
```

## Примечания

- Для использования main_new.c замените main.c в проекте
- Права администратора рекомендуются для полной функциональности
- Архитектура x64 требуется для descriptor_checks и timing_checks

## Тестовый проект

Solution включает проект `hyperv_detector_tests` для проверки каждого метода детекции на различных конфигурациях.

### Запуск тестов

```
hyperv_detector_tests.exe [опции]

Опции:
  --json           Вывод в формате JSON
  --config <имя>   Название конфигурации для отчёта
  --help           Справка
```

### Примеры

```bash
# Запуск на гостевой VM
hyperv_detector_tests.exe --config "VM-Windows11"

# JSON вывод для автоматизации
hyperv_detector_tests.exe --json --config "HyperV-Host"
```

### Категории тестов

| Категория | Описание |
|-----------|----------|
| CPUID | Проверка CPUID листов гипервизора |
| Registry | Ключи реестра Hyper-V |
| Services | Сервисы Hyper-V |
| Devices | Устройства Hyper-V |
| Files | Файлы драйверов (vmbus.sys, vmbusr.sys) |
| Processes | Процессы Hyper-V |
| WMI | WMI запросы |
| MAC | MAC-адреса виртуальных адаптеров |
| PerfCounter | Счётчики производительности |
| RootPartition | Определение root/guest partition |

### Авто-определение конфигурации

Тесты автоматически определяют тип системы:
- `BareMetal` - нет гипервизора
- `HyperV-RootPartition` - хост Hyper-V
- `HyperV-GuestVM` - гостевая VM
- `OtherHypervisor-<vendor>` - другой гипервизор

## Лицензия

Свободное использование
