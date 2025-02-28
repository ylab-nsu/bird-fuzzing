import os

class TestResults:
    """Класс для хранения результатов тестов"""
    def __init__(self):
        self.results = []

    def add_result(self, test_name, status, number_tests, time, details=""):
        """Добавляет результат теста"""
        self.results.append({
            "test": test_name,
            "status": status,
            "number tests": number_tests,
            "time": time,
            "details": details
        })

    def generate_html_report(self, output_dir="output", output_file="report.html"):
        """Генерирует HTML-отчёт и сохраняет в указанную папку"""
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, output_file)
        
        html = "<html><head><title>Test Report</title></head><body>"
        html += "<h1>BGP Fuzzing Test Report</h1>"
        html += "<table border='1'><tr><th>Test</th><th>Status</th><th>Number of Tests</th><th>Time</th><th>Details</th></tr>"
        for result in self.results:
            html += f"<tr><td>{result['test']}</td><td>{result['status']}</td><td>{result['number tests']}</td><td>{result['time']}</td><td>{result['details']}</td></tr>"
        html += "</table></body></html>"

        with open(output_path, "w") as f:
            f.write(html)
