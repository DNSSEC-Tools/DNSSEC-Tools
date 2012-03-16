var hosts = []
var tests = []
var rawtests = []
var testNumber = 0
var hosttests = {}
var numTests = 11
var numColumns = numTests + 1
var currentTestHost = ""

function loadInitial() {
    hosts = testManager.loadResolvConf();

    createAllComponents();
}

function clearServers() {
    tests = []
    hosts = []
    rawtests = []
    hosttests = {}
    for(var i = resultGrid.children.length; i > 0 ; i--) {
        resultGrid.children[i-1].destroy()
    }
    dnssecCheckTop.state = "cleared"
}

function removeHost(host) {
    for(var i = tests.length; i > 0 ; i--) {
        if (tests[i-1].test.serverAddress == host) {
            console.log("removing: " + (i-1))
            tests.splice(i-1,1)
            resultGrid.children[i + Math.floor((i-1) / numTests)].destroy()
        }
    }
    for(var i = resultGrid.children.length; i > 0; i--) {
        if (resultGrid.children[i-1].hostName == host) {
            resultGrid.children[i-1].destroy()
        }
    }
}

function clearHost(host) {
    for(var i = tests.length; i > 0 ; i--) {
        if (tests[i-1].test.serverAddress == host) {
            tests[i-1].test.status = DNSSECTest.UNKNOWN
        }
    }
}

function testHost(host) {
    clearHost(host)
    currentTestHost = host
    console.log("starting tests for '" + currentTestHost + "'")
    runAllTests()
}

function haveAllTestsRun() {
    for(var i = tests.length; i > 0 ; i--) {
        if (tests[i-1].test.status == DNSSECTest.UNKNOWN)
            return false
    }
    return true
}

function makeLight(creator, type, name, host) {
    var result = creator.createObject(resultGrid)
    result.name = name
    result.test = testManager.makeTest(type, host, name);
    tests.push(result)
    rawtests.push(result.test)
    hosttests[host].push(result.test)
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
    hosttests[host] = [];

    // var result = makeLight(resultComponent, testManager.basic_dns, "DNS", host)
    var result = makeLight(resultComponent, 0, "DNS", host)
    label.height = result.height // set the label height to the bubble height so it vcenters properly

    makeLight(resultComponent, 1, "TCP", host)
    makeLight(resultComponent, 2, "DO", host)
    makeLight(resultComponent, 3, "AD", host)
    makeLight(resultComponent, 4, "RRSIG", host)
    makeLight(resultComponent, 5, "EDNS0", host)
    makeLight(resultComponent, 6, "NSEC", host)
    makeLight(resultComponent, 7, "NSEC3", host)
    makeLight(resultComponent, 8, "DNSKEY", host)
    makeLight(resultComponent, 9, "DS", host)
    makeLight(resultComponent, 10, "DNS", host)

    // XXX: for some reason the enums aren't working:
    // makeLight(resultComponent, testManager.basic_tcp, "TCP", host)
    // makeLight(resultComponent, testManager.do_bit, "DO", host)
    // makeLight(resultComponent, testManager.ad_bit, "AD", host)
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
    resultGrid.columns = numColumns

    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")

    for(var host in hosts) {
        addHost(labelComponent, resultComponent, hosts[host])
    }
}

function runAllTests() {
    if (currentTestHost == "") {
        resetTests()
    }
    testNumber = -1;
    dnssecCheckTop.state = "running"
    setTestStartMessage();
    console.log("starting tests for '" + currentTestHost + "'")
    runNextTest();
}

function runNextTest() {
    testNumber++

    // find itmes from the specific host we want to test, if not all of them
    while (currentTestHost != "" && testNumber < tests.length && tests[testNumber].test.serverAddress != currentTestHost) {
        testNumber++
    }

    if (testNumber < tests.length) {
	tests[testNumber].test.check();
        timer.start();
        setTestStartMessage()
    } else {
        timer.stop()
        if (currentTestHost == "" || haveAllTestsRun())
            dnssecCheckTop.state = "ran"
        else
            dnssecCheckTop.state = "half"
        testStatusMessage.text = ""
        testResultMessage.text = "All tests have completed; hover over a result for details"
        currentTestHost = ""
    }
}

function setTestStartMessage() {
    if (testNumber + 1 < tests.length) {
        testStatusMessage.text =
                "Test Status: sending test for " + tests[testNumber+1].test.name + " to " + tests[testNumber+1].test.serverAddress
    }
}

function resetTests() {
    for(var result in tests) {
        tests[result].test.status = DNSSECTest.UNKNOWN
    }
    dnssecCheckTop.state = ""
}

function submitResults() {
    var datalist = [];
    var count = 0;
    for(var host in hosttests) {
        datalist.push("server" + count)
        datalist.push(testManager.sha1hex(host))
        for (var testnum in hosttests[host]) {
            var test = hosttests[host][testnum]
            datalist.push(test.name + count)
            datalist.push(test.status)
        }
        count++;
    }
    testManager.submitResults(datalist)
}
