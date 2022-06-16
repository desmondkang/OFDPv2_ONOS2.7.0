COMPILE_DEPS = CORE_DEPS + KRYO + CLI

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.foo"],
    deps = COMPILE_DEPS,
)

onos_app(
    app_name = "org.onosproject.foo",
    category = "default",
    description = "ONOS OSGi bundle archetype",
    title = "Foo App",
    url = "http://onosproject.org",
)
