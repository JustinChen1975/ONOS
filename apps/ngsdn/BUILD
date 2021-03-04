COMPILE_DEPS = CORE_DEPS + JACKSON + REST + CLI + KRYO + [
    "//core/common:onos-core-common",
    "//protocols/p4runtime/model:onos-protocols-p4runtime-model",
    "//protocols/p4runtime/api:onos-protocols-p4runtime-api",
    "//drivers/default:onos-drivers-default",
    "//core/store/serializers:onos-core-serializers",
    #    "//apps/inbandtelemetry/api:onos-apps-inbandtelemetry-api",
]

#
#COMPILE_DEPS = CORE_DEPS + KRYO + [
#    "//core/store/serializers:onos-core-serializers",
#    "//pipelines/basic:onos-pipelines-basic",
#    "//apps/inbandtelemetry/api:onos-apps-inbandtelemetry-api",
#]

osgi_jar_with_tests(
    #    api_description = "NG-SDN tutorial app",
    api_package = "com.cxc.ngsdn",
    api_title = "NG-SDN App v1.0",
    api_version = "/onos/v1/ngsdn",
    karaf_command_packages = ["com.cxc.ngsdn.cli"],
    deps = COMPILE_DEPS,
    #    web_context = "/onos/Mao",
)

#BUNDLES = [
#    "//pipelines/basic:onos-pipelines-basic",
#    "//apps/inbandtelemetry/api:onos-apps-inbandtelemetry-api",
#]

#REQUIRE_APPS = [
#    "org.onosproject.proxyarp",
#]

onos_app(
    category = "Traffic Steering",
    description = "Provides IPv6 routing capabilities to a leaf-spine network of Stratum switches",
    title = "NG-SDN",
    url = "http://127.0.0.1",
    #    required_apps = REQUIRE_APPS,
)

#onos_app(
#    app_name = "org.onosproject.pipelines.basic",
#    category = "Pipeline",
#    description = "Provides pipelines with basic L2/L3 forwarding capabilities and packet-in/out " +
#                  "support.",
#    included_bundles = BUNDLES,
#    required_apps = [
#        "org.onosproject.drivers.p4runtime",
#    ],
#    title = "Basic Pipelines",
#    url = "http://onosproject.org",
#)
