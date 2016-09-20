from getdns.getdns import validate_ip


def test_validate_ip():
    assert validate_ip("1.1.1") == False
    assert validate_ip("255.255.255.255") == True
    assert validate_ip("1.1.1.256") == False
    assert validate_ip("1.1.1.-1") == False
