import os
import shutil
import pytest
from .test_results import ResultsContainer

def pytest_addoption(parser):
    parser.addoption("--max-tests", action="store", default=10000, help="Number of max tests to run")

@pytest.fixture
def max_tests(request):
    return int(request.config.getoption("--max-tests"))

@pytest.fixture(scope="session")
def test_results():
    """Создаем один объект ResultsContainer на всю сессию и сохраняем в session.config"""
    results = ResultsContainer()
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
    bfd_logs_file = 'bfd_fuzz_logs.txt'
    if os.path.exists(bfd_logs_file):
        shutil.move(bfd_logs_file, os.path.join(output_dir, bfd_logs_file))

    # Перемещение результатов boofuzz
    results_dir = 'boofuzz-results'
    if os.path.exists(results_dir):
        shutil.move(results_dir, os.path.join(output_dir, results_dir))

    print(f"\n✅ Результаты тестов сохранены в {output_dir}/")
