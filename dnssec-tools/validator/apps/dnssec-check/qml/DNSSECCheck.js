var hosts = [];
var tests = [];

function loadInitial() {
    hosts = testManager.loadResolvConf();

    createAllComponents();
}

function makeLight(creator, type, name, host) {
    console.log("test type " + type + " for host " + host)
    var result = creator.createObject(resultGrid)
    result.name = name
    result.test = testManager.makeTest(type, host, name);
    tests.push(result)
    return result
}

function addHost(labelComponent, resultComponent, host) {
    var label = labelComponent.createObject(resultGrid)

    label.hostName = hosts[host]

    // var result = makeLight(resultComponent, testManager.basic_dns, "DNS", hosts[host])
    var result = makeLight(resultComponent, 0, "DNS", hosts[host])
    label.height = result.height // set the label height to the bubble height so it vcenters properly

    makeLight(resultComponent, 1, "TCP", hosts[host])
    makeLight(resultComponent, 2, "DO", hosts[host])
    makeLight(resultComponent, 3, "RRSIG", hosts[host])
    makeLight(resultComponent, 4, "EDNS0", hosts[host])
    makeLight(resultComponent, 5, "NSEC", hosts[host])
    makeLight(resultComponent, 6, "NSEC3", hosts[host])
    makeLight(resultComponent, 7, "DNSKEY", hosts[host])
    makeLight(resultComponent, 8, "DS", hosts[host])

    // XXX: for some reason the enums aren't working:
    // makeLight(resultComponent, testManager.basic_tcp, "TCP", hosts[host])
    // makeLight(resultComponent, testManager.do_bit, "DO", hosts[host])
    // makeLight(resultComponent, testManager.do_has_rrsigs, "RRSIG", hosts[host])
    // makeLight(resultComponent, testManager.small_edns0, "EDNS0", hosts[host])
    // makeLight(resultComponent, testManager.can_get_nsec, "NSEC", hosts[host])
    // makeLight(resultComponent, testManager.can_get_nsec3, "NSEC3", hosts[host])
    // makeLight(resultComponent, testManager.can_get_dnskey, "DNSKEY", hosts[host])
    // makeLight(resultComponent, testManager.can_get_ds, "DS", hosts[host])
}

function createAllComponents() {
    tests = [];

    resultGrid.rows = hosts.length
    resultGrid.columns = 10

    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")

    for(var host in hosts) {
        addHost(labelComponent, resultComponent, host)
    }
}

function runAllTests() {
    for(var result in tests) {
        console.log("here: " + result + " - " + tests[result])
        tests[result].test.check();
        console.log("result: " + tests[result].test.message)
    }
}
