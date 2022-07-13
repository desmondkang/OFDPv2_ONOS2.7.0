COMPILE_DEPS = CORE_DEPS + CLI

REQUIRED_APPS = [
    "org.onosproject.fwd",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.oneping.cli"],
    test_deps = TEST_ADAPTERS,
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.oneping",
    category = "Traffic Engineering",
    description = "Controls ICMP traffic between any two specific hosts, " +
                  "allow only two hosts to deliver only one ICMP traffic " +
                  "within 60 seconds.",
    required_apps = REQUIRED_APPS,
    title = "One Ping",
    url = "http://onosproject.org",
)
