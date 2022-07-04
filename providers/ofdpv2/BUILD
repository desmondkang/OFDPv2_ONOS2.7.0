COMPILE_DEPS = CORE_DEPS + NETTY + JACKSON + METRICS + CLI + [
    "@openflowj//jar",
    "//protocols/openflow/api:onos-protocols-openflow-api",
    "//apps/switchportlookup:onos-apps-switchportlookup",
]

APPS = [
    "org.onosproject.switchportlookup",
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
    description = "OFDPv2 - Provides link discovery to the ONOS core by eavesdropping on the LLDP control packets.",
    included_bundles = BUNDLES,
    required_apps = APPS,
    title = "OFDPv2 - LLDP Link Provider",
    url = "http://onosproject.org",
)
