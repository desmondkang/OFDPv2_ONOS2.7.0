COMPILE_DEPS = CORE_DEPS + CLI

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.packetsniffer.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.packetsniffer",
    category = "Traffic Engineering",
    description = "Intercept ALL inbound traffic and display on CLI ",
    title = "Packet Sniffer",
    url = "http://onosproject.org",
)
