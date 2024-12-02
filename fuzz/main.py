import json
from bgp_fuzz_open_message import BGPFuzzOpenMessage


# Fuzzing test
bgp_test = BGPFuzzOpenMessage('config.json')
bgp_test.fuzz_open_and_keepalive()
