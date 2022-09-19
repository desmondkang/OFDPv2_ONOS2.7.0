COMPILE_DEPS = CORE_DEPS + NETTY + JACKSON + CLI + [
    "//protocols/openflow/api:onos-protocols-openflow-api",
]

BUNDLES = [
    "//providers/ofdpv2:onos-providers-ofdpv2",
]

osgi_jar_with_tests(
    karaf_command_packages =
        [
            "org.onosproject.provider.ofdpv2.cli",
        ],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.ofdpv2provider",
    category = "Provider",
    description = "Provides link discovery to the ONOS core by eavesdropping" +
                  " on the LLDP control packets using OpenFlow Discovery" +
                  " Protocol v2 (OFDPv2) Approach.",
    included_bundles = BUNDLES,
    title = "OFDPv2 - LLDP Link Provider",
    url = "http://onosproject.org",
)
