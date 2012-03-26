var hosts = []
var tests = []
var rawtests = []
var testNumber = 0
var hosttests = {}
var hostgrades = {}
var numTests = 10
var numLeftColumns = 2
var numColumns = numTests + numLeftColumns
var numHeaders = numColumns
var currentTestHost = ""

function getColumns() {
    return numColumns
}

function loadInitial() {
    hosts = testManager.loadResolvConf();

    createAllComponents();
    dnssecCheckTop.state = ""
}

function clearServers() {
    tests = []
    hosts = []
    rawtests = []
    hosttests = {}
    for(var i = resultGrid.children.length; i > numHeaders ; i--) {
        resultGrid.children[i-1].destroy()
    }
    dnssecCheckTop.state = "cleared"
}

function removeHost(host) {
    for(var i = tests.length; i > 0 ; i--) {
        if (tests[i-1].test.serverAddress == host) {
            tests.splice(i-1,1)
            resultGrid.children[numHeaders + (i-1) + numLeftColumns*Math.floor(1+(i-1) / numTests)].destroy()
        }
    }


    for(var i = resultGrid.children.length; i > numHeaders; i--) {
        if (resultGrid.children[i-1].hostName == host) {
            resultGrid.children[i-1].destroy()
        }
        if (resultGrid.children[i-1] === hostgrades[host]) {
            resultGrid.children[i-1]
        }
    }

    hostgrades[host].destroy();
    delete hostgrades[host];
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
    runAllTests()
}

function haveAllTestsRun() {
    assignHostGrade();
    for(var i = tests.length; i > 0 ; i--) {
        if (tests[i-1].test.status === DNSSECTest.UNKNOWN || tests[i-1].test.status === DNSSECTest.TESTINGNOW) {
            console.log("test not done: " + i)
            return false
        }
    }
    return true
}

function assignHostGrade() {
    var grades = ['A', 'B', 'C', 'D', 'F'];

    for(var i = 0 ; i < hosts.length; i++) {
        var hostname = hosts[i]
        var hostarray = hosttests[hostname]
        var finished = true
        var maxGrade = 0

        for(var j = 0; j < hosttests[hostname].length; j++) {
            if (hosttests[hostname][j].status == DNSSECTest.UNKNOWN)
                finished = false

            // Check for any failure == at least a B
            if (hosttests[hostname][j].status != DNSSECTest.GOOD) {
                maxGrade = Math.max(maxGrade, 1);
            }

            if (hosttests[hostname][j].name == "DNS" && hosttests[hostname][j].status != DNSSECTest.GOOD) {
                maxGrade = Math.max(4, maxGrade);
            }

            // if they can't do the DNSSEC specific tests (DO, RRSIG, NSEC, NSEC3, DNSKEY, DS) they get a C
            if ((hosttests[hostname][j].name == "TCP" ||
                 hosttests[hostname][j].name == "DO" ||
                 hosttests[hostname][j].name == "RRSIG" ||
                 hosttests[hostname][j].name == "NSEC" ||
                 hosttests[hostname][j].name == "NSEC3" ||
                 hosttests[hostname][j].name == "DNSKEY" ||
                 hosttests[hostname][j].name == "DS") &&
                    hosttests[hostname][j].status != DNSSECTest.GOOD) {
                maxGrade = Math.max(2, maxGrade);
            }

            // If they fail EDNS0, then it's a D
            if (hosttests[hostname][j].name == "EDNS0" && hosttests[hostname][j].status != DNSSECTest.GOOD) {
                maxGrade = Math.max(3, maxGrade);
            }
        }
        if (!finished)
            hostgrades[hosts[i]].grade = "?"
        else
            hostgrades[hosts[i]].grade = grades[maxGrade]
    }
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
    if (!testManager.testName(host)) {
        hostErrorMessage.state = "visible"
        hostErrorMessage.resolverAddress = host
        return; // XXX: add an error message
    }

    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")
    var hostComponent   = Qt.createComponent("Grade.qml")

    hosts.push(host)
    resultGrid.rows = resultGrid.rows + 1
    addHost(labelComponent, resultComponent, hostComponent, host)
}

function addHost(labelComponent, resultComponent, hostComponent, host) {
    var label = labelComponent.createObject(resultGrid)
    var hostGrade = hostComponent.createObject(resultGrid)

    label.hostName = host
    hosttests[host] = [];
    hostgrades[host] = hostGrade;

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

    // makeLight(resultComponent, 10, "DNS", host) // libval async testing only

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

    resultGrid.rows = hosts.length + 1
    resultGrid.columns = numColumns

    var resultComponent = Qt.createComponent("Result.qml")
    var labelComponent  = Qt.createComponent("HostLabel.qml")
    var hostComponent   = Qt.createComponent("Grade.qml")

    if (hostComponent.status != Component.Ready) {
        console.log(hostComponent.errorString())
    }

    for(var host in hosts) {
        addHost(labelComponent, resultComponent, hostComponent, hosts[host])
    }
}

function runAllTests() {
    if (currentTestHost == "") {
        resetTests()
    }
    testNumber = -1;
    dnssecCheckTop.state = "running"
    testManager.inTestLoop = true;
    setTestStartMessage();
    console.log("starting tests for '" + currentTestHost + "'")
    giveUpTimer.start()
    countingTimer.start()
    runNextTest();
}

function runNextTest() {
    testNumber++

    // find itmes from the specific host we want to test, if not all of them
    while (currentTestHost != "" && testNumber < tests.length && tests[testNumber].test.serverAddress !== currentTestHost) {
        testNumber++
    }

    if (testNumber < tests.length) {
        tests[testNumber].test.check();
        timer.start();
        setTestStartMessage()
    } else {
        testManager.inTestLoop = false;
        if (testManager.outStandingRequests() > 0) {
            testManager.startQueuedTransactions();
            testManager.checkAvailableUpdates();
            testManager.dataAvailable();
            timer.start();
            return;
        }
        stopTesting();
    }
}

function stopTesting() {
    timer.stop()
    giveUpTimer.stop()
    countingTimer.stop()
    testManager.inTestLoop = false;
    testManager.checkAvailableUpdates();
    console.log("current host: '" + currentTestHost + "' => " + (currentTestHost == ""))
    if (currentTestHost === "" || haveAllTestsRun())
        dnssecCheckTop.state = "ran"
    else
        dnssecCheckTop.state = "half"
    testStatusMessage.text = ""
    testResultMessage.text = "All tests have completed; Click on a bubble for details"
    currentTestHost = ""
    assignHostGrade();
}

function cancelTests() {
    for(var i = 0; i < tests.length; i++) {
        if (tests[i].test.status == DNSSECTest.TESTINGNOW)
        tests[i].test.status = DNSSECTest.BAD
    }
    stopTesting()
}

function giveUpTimerHook() {
    // if we get here, we're fairly sunk as it's taken a long time for the requests to complete.
    // So we give up.
    console.log("giving up")
    giveUpMessage.state = "visible"
    cancelTests()
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
    for(var host in hosts) {
        hostgrades[hosts[host]].grade = "?"
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
