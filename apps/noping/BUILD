COMPILE_DEPS = CORE_DEPS + CLI

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.noping.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.noping",
    category = "Traffic Engineering",
    description = "Block all ICMP Traffic",
    title = "No Ping",
    url = "http://onosproject.org",
)
