import json
from bgp_fuzz_open_message import BGPFuzzOpenMessage
from bgp_fuzz_notification_message import BGPFuzzNotificationMessage
from bgp_fuzz_update_message import BgpUpdateFuzzer


# Fuzzing Open Message
bgp_test = BGPFuzzOpenMessage('config.json')
#bgp_test.fuzz_bgp_open_with_optional_params()
#bgp_test.fuzz_bgp_open_optional_param_length()
#bgp_test.fuzz_bgp_open_random_params()
#bgp_test.fuzz_bgp_open_version_field()
#bgp_test.fuzz_bgp_open_length_mismatch()
#bgp_test.fuzz_open_asn()
bgp_test.fuzz_open_hold_time()
#bgp_test.fuzz_open_identifier()
#bgp_test.fuzz_open_version_length()

#bgp_test2 = BGPFuzzNotificationMessage('config.json')
#bgp_test2.fuzz_notification()

bgp_test3 = BgpUpdateFuzzer('config.json')
#bgp_test3.fuzz_bgp_messages()
#bgp_test3.fuzz_bgp_messages2()
