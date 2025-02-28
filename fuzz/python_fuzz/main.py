import os
import shutil
from test_results import TestResults
from bgp_fuzz_open_message import BGPFuzzOpenMessage
from bgp_fuzz_notification_message import BGPFuzzNotificationMessage
from bgp_fuzz_update_message import BgpUpdateFuzzer

# Создаём объект для хранения результатов
test_results = TestResults()

# Fuzzing Open Message
# bgp_test1 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test1.fuzz_bgp_open_with_optional_params()
# bgp_test2 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test2.fuzz_bgp_open_optional_param_length()
# bgp_test3 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test3.fuzz_bgp_open_random_params()
# bgp_test4 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test4.fuzz_bgp_open_version_field()
# bgp_test5 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test5.fuzz_bgp_open_length_mismatch()  # посмотреть что там
# bgp_test6 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test6.fuzz_open_asn()
# bgp_test7 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test7.fuzz_open_hold_time()
# bgp_test8 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test8.fuzz_open_identifier()
# bgp_test9 = BGPFuzzOpenMessage('config.json', test_results)
# bgp_test9.fuzz_open_version_length()  # посмотреть что там

# bgp_test10 = BGPFuzzNotificationMessage('config.json', test_results)
# bgp_test10.fuzz_notification()

bgp_test11 = BgpUpdateFuzzer('config.json', test_results)
bgp_test11.update_test_with_withdrawn_routes()
bgp_test11.update_test_fuzz_withdrawn_routes_length()
bgp_test11.update_test_fuzz_path_attributes_length()
#bgp_test11.update_test_fuzz_path_attributes()  # посмотреть что там
bgp_test11.update_test_fuzz_nlri()

# Сохранение результатов
output_dir = 'output'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

test_results.generate_html_report(output_dir=output_dir)

logs_file = 'logs.txt'
if os.path.exists(logs_file):
    shutil.move(logs_file, os.path.join(output_dir, logs_file))

results_dir = 'boofuzz-results'
if os.path.exists(results_dir):
    shutil.move(results_dir, os.path.join(output_dir, results_dir))