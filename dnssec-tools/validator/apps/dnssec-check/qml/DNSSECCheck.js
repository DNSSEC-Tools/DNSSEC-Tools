var hosts = [];
var tests = [];

function loadInitial() {
    hosts = testManager.loadResolvConf();

    createAllComponents();
}

function makeLight(creator, type, name, host) {
    var result = creator.createObject(resultGrid)
    result.name = name
    result.test = testManager.makeTest(type, host, name);
    tests.push(result)
    return result
}

function addSingleHost(host) {
    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")
    hosts.push(host)
    resultGrid.rows = resultGrid.rows + 1
    addHost(labelComponent, resultComponent, host)
}

function addHost(labelComponent, resultComponent, host) {
    var label = labelComponent.createObject(resultGrid)

    label.hostName = host

    // var result = makeLight(resultComponent, testManager.basic_dns, "DNS", host)
    var result = makeLight(resultComponent, 0, "DNS", host)
    label.height = result.height // set the label height to the bubble height so it vcenters properly

    makeLight(resultComponent, 1, "TCP", host)
    makeLight(resultComponent, 2, "DO", host)
    makeLight(resultComponent, 3, "RRSIG", host)
    makeLight(resultComponent, 4, "EDNS0", host)
    makeLight(resultComponent, 5, "NSEC", host)
    makeLight(resultComponent, 6, "NSEC3", host)
    makeLight(resultComponent, 7, "DNSKEY", host)
    makeLight(resultComponent, 8, "DS", host)

    // XXX: for some reason the enums aren't working:
    // makeLight(resultComponent, testManager.basic_tcp, "TCP", host)
    // makeLight(resultComponent, testManager.do_bit, "DO", host)
    // makeLight(resultComponent, testManager.do_has_rrsigs, "RRSIG", host)
    // makeLight(resultComponent, testManager.small_edns0, "EDNS0", host)
    // makeLight(resultComponent, testManager.can_get_nsec, "NSEC", host)
    // makeLight(resultComponent, testManager.can_get_nsec3, "NSEC3", host)
    // makeLight(resultComponent, testManager.can_get_dnskey, "DNSKEY", host)
    // makeLight(resultComponent, testManager.can_get_ds, "DS", host)
}

function createAllComponents() {
    tests = [];

    resultGrid.rows = hosts.length
    resultGrid.columns = 10

    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")

    for(var host in hosts) {
        addHost(labelComponent, resultComponent, hosts[host])
    }
}

function runAllTests() {
    for(var result in tests) {
        tests[result].test.check();
    }
}
