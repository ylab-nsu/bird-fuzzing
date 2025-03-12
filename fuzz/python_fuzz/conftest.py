import os
import shutil
import pytest
from test_results import TestResults

@pytest.fixture(scope="session")
def test_results():
    """Создаем один объект TestResults на всю сессию и сохраняем в session.config"""
    results = TestResults()
    pytest.test_results = results  # Сохраняем в pytest
    return results

@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """Функция выполняется после всех тестов"""
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Получаем test_results из pytest
    test_results = getattr(pytest, "test_results", None)
    if test_results:
        test_results.generate_html_report(output_dir=output_dir)

    # Перемещение логов
    logs_file = 'logs.txt'
    if os.path.exists(logs_file):
        shutil.move(logs_file, os.path.join(output_dir, logs_file))

    # Перемещение результатов boofuzz
    results_dir = 'boofuzz-results'
    if os.path.exists(results_dir):
        shutil.move(results_dir, os.path.join(output_dir, results_dir))

    print(f"\n✅ Результаты тестов сохранены в {output_dir}/")
