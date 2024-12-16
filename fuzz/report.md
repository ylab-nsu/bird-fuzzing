# Отчёт по тестам

## Notification
Test 1
The error code, error subcode, and error data are fuzzable, with the error data being a random fuzzload.

## Open message
Test 1
Fuzzes the BGP Open message with multiple optional parameters, each having a random payload.

Test 2
Fuzzes the length of optional parameters (1 octet) and their payload.

Test 3
Fuzzes optional parameters with random payload and length.

Test 4
Fuzzes the BGP version field with random and boundary values.

Test 5
Fuzzes the BGP header length to create a mismatch with the actual message size.

Test 6
Fuzz ASN field with boundary and random values.

Test 7
Fuzz Hold Time field with boundary and random values.

Test 8
Fuzz BGP Identifier field with random values and invalid IPs.

Test 9
Fuzzes the BGP version field and the packet length field with mismatched values.

## Update
