APPS = [
    "org.onosproject.hostprovider",
    "org.onosproject.ofdpv2provider",
    "org.onosproject.openflow-base_ofdpv2",
]

onos_app(
    app_name = "org.onosproject.openflow_ofdpv2",
    category = "Provider",
    description = "Suite of the OpenFlow base providers bundled together with ARP/NDP host " +
                  "location provider and LLDP link provider using OFDPv2 Approach.",
    included_bundles = ["//utils/osgi:onlab-osgi"],  # FIXME to allow hollow oar files
    required_apps = APPS,
    title = "OFDPv2 - OpenFlow Provider Suite",
    url = "http://onosproject.org",
)
