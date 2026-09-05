from cvex.cpe import parse_cpe, same_product


def test_parse_cpe_22():
    parsed = parse_cpe("cpe:/a:haxx:curl:7.87.0")
    assert parsed is not None
    assert parsed.version == "2.2"
    assert parsed.part == "a"
    assert parsed.vendor == "haxx"
    assert parsed.product == "curl"
    assert parsed.component_version == "7.87.0"


def test_parse_cpe_23_and_compare_product():
    left = parse_cpe("cpe:/a:haxx:curl:7.87.0")
    right = parse_cpe("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*")
    assert left is not None
    assert right is not None
    assert same_product(left, right)
    assert right.component_version is None
