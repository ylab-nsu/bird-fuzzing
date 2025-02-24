from boofuzz import IFuzzLogger

class CustomFuzzLogger(IFuzzLogger):
    def __init__(self, log_file):
        self.log_file = log_file
        self.current_test_case_id = None
        self.current_test_step_description = None

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self.current_test_case_id = test_case_id
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Test Case: {test_case_id} - {name} (Index: {index})\n")

    def close_test_case(self):
        pass

    def open_test_step(self, description):
        pass

    def close_test_step(self):
        pass

    def log_send(self, data):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Send: {data.hex()}\n")

    def log_recv(self, data):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Recv: {data.hex()}\n")

    def log_check(self, description):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Check: {description}\n")

    def log_pass(self, description=''):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Check Passed: {description}\n")

    def log_fail(self, description=''):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Check Failed: {description}\n")

    def log_info(self, description):
        pass

    def log_error(self, description):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"Error: {description}\n")

    def close_test(self):
        pass

