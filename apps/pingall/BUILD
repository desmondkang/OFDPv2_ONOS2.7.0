COMPILE_DEPS = CORE_DEPS + CLI

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.pingall.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.pingall",
    category = "Traffic Engineering",
    description = "Allow all ICMP Traffic",
    title = "Ping All",
    url = "http://onosproject.org",
)
