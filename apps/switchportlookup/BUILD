COMPILE_DEPS = CORE_DEPS + CLI

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.switchportlookup.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.switchportlookup",
    category = "Traffic Engineering",
    description = "One-to-one mapping of switchport mac address to a connectpoint",
    title = "Switchport Lookup",
    url = "http://onosproject.org",
)
