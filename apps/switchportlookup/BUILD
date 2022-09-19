COMPILE_DEPS = CORE_DEPS + CLI + [
    "@openflowj//jar",
    "//protocols/openflow/api:onos-protocols-openflow-api",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.switchportlookup.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.switchportlookup",
    category = "Debug",
    description = "One-to-one mapping of switchport MAC Address to their DeviceID",
    title = "Switchport Lookup",
    url = "http://onosproject.org",
)
