COMPILE_DEPS = CORE_DEPS

osgi_jar_with_tests(
    karaf_command_packages = [],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.fakeping",
    category = "Traffic Engineering",
    description = "Install Flow Rule on OF Switch to generate" +
                  "fake reply to ICMP Sender",
    title = "Fake Ping",
    url = "http://onosproject.org",
)
