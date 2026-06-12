# Генераторы артефактов

- `make_xlsx.py` — dependency-free .xlsx writer
- `make_template_xlsx.py` — собирает docs/testing/TaMP_proj6_Testing.xlsx (формат учебного шаблона)

Запуск (из корня репозитория):
```bash
python3 tools/make_xlsx.py
python3 tools/make_template_xlsx.py
```

Диаграммы: `java -jar plantuml.jar -tpng docs/diagrams/*.puml`
