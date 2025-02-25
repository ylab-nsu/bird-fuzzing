from bgp_fuzz_open_message import BGPFuzzOpenMessage
from bgp_fuzz_notification_message import BGPFuzzNotificationMessage
from bgp_fuzz_update_message import BgpUpdateFuzzer


# Fuzzing Open Message
bgp_test1 = BGPFuzzOpenMessage('config.json')
bgp_test1.fuzz_bgp_open_with_optional_params()
bgp_test2 = BGPFuzzOpenMessage('config.json')
bgp_test2.fuzz_bgp_open_optional_param_length()
bgp_test3 = BGPFuzzOpenMessage('config.json')
bgp_test3.fuzz_bgp_open_random_params()
bgp_test4 = BGPFuzzOpenMessage('config.json')
bgp_test4.fuzz_bgp_open_version_field()
bgp_test5 = BGPFuzzOpenMessage('config.json')
bgp_test5.fuzz_bgp_open_length_mismatch() # посмотреть что там
bgp_test6 = BGPFuzzOpenMessage('config.json')
bgp_test6.fuzz_open_asn()
bgp_test7 = BGPFuzzOpenMessage('config.json')
bgp_test7.fuzz_open_hold_time()
bgp_test8 = BGPFuzzOpenMessage('config.json')
bgp_test8.fuzz_open_identifier()
bgp_test9 = BGPFuzzOpenMessage('config.json')
bgp_test9.fuzz_open_version_length()  #посмотреть что там

bgp_test10 = BGPFuzzNotificationMessage('config.json')
bgp_test10.fuzz_notification()

bgp_test11 = BgpUpdateFuzzer('config.json')
bgp_test11.update_test_with_withdrawn_routes()
bgp_test11.update_test_fuzz_withdrawn_routes_length()
bgp_test11.update_test_fuzz_path_attributes_length()
#bgp_test11.update_test_fuzz_path_attributes() # посмотреть что там
bgp_test11.update_test_fuzz_nlri()