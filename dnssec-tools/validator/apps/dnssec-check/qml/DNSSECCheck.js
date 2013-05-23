// XXX: most of these should be combined into a single associative array per host rather than have
// a bunch of independent structures (ie, fix the feature creep mess)

var hosts = []
var tests = []
var numTests = 11
var numLeftColumns = 2
var numColumns = numTests + numLeftColumns
var numHeaders = numColumns
var currentSingleTestHost = ""
var currentTestHostNum = 0
var currentTestNumber = 0
var restartCount = 0

var hostInfo = {}
// Keys to host info:
//   tests:   test objects in use (ie, a C++ DNSSECTest object)
//   grades:  grade objects
//

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
    hostInfo = {}
    for(var i = resultGrid.children.length; i > numHeaders ; i--) {
        resultGrid.children[i-1].destroy()
    }
    dnssecCheckTop.state = "cleared"
}

function getHostIndex(host) {
    for(var i = hosts.length - 1; i >= 0; i--) {
        if(hosts[i] === host) {
            return i
        }
    }
    return -1
}

function removeHost(host) {
    var myHostNum = getHostIndex(host)

    // destroy all the test lights
    for(var i = hostInfo[host]['tests'].length - 1; i >= 0 ; i--) {
        resultGrid.children[numHeaders + myHostNum * (numTests + numLeftColumns) + i + numLeftColumns].destroy()
    }

    // destroy the grade object
    resultGrid.children[numHeaders + myHostNum * (numTests + numLeftColumns) + 1].destroy()

    // destroy the host label object
    resultGrid.children[numHeaders + myHostNum * (numTests + numLeftColumns)].destroy()

    // remove us from the numeric host list
    hosts.splice(myHostNum, 1)

    delete hostInfo[host]
}

function clearHost(host) {
    for(var i = hostInfo[host]['tests'].length - 1; i >= 0 ; i--) {
        hostInfo[host]['tests'][i].test.status = DNSSECTest.UNKNOWN
    }
}

function testHost(host) {
    clearHost(host)
    currentSingleTestHost = host
    currentTestHostNum = getHostIndex(host)
    runAllTests()
}

function haveAllTestsRun() {
    assignHostGrade();
    for(var host = hosts.length - 1; host >= 0; host--) {
        var hostName = hosts[host]
        for(var testnum = hostInfo[hostName]['tests'].length - 1; testnum >= 0; testnum--) {
            if (hostInfo[hostName]['tests'][testnum].test.status === DNSSECTest.UNKNOWN ||
                hostInfo[hostName]['tests'][testnum].test.status === DNSSECTest.TESTINGNOW) {
                return false
            }
        }
    }
    return true
}

function assignHostGrade() {
    var grades = ['A', 'B', 'C', 'D', 'F'];

    for(var i = 0 ; i < hosts.length; i++) {
        var hostName = hosts[i]
        var finished = true
        var maxGrade = 0

        for(var j = 0; j < hostInfo[hostName]['tests'].length; j++) {
            var testObject = hostInfo[hostName]['tests'][j].test
            if (testObject.status == DNSSECTest.UNKNOWN)
                finished = false

            // Check for any failure == at least a B
            if (testObject.status != DNSSECTest.GOOD) {
                maxGrade = Math.max(maxGrade, 1);
            }

            if (testObject.name == "DNS" && testObject.status != DNSSECTest.GOOD) {
                maxGrade = Math.max(4, maxGrade);
            }

            // if they can't do the DNSSEC specific tests (DO, RRSIG, NSEC, NSEC3, DNSKEY, DS) they get a C
            if ((testObject.name == "TCP" ||
                 testObject.name == "DO" ||
                 testObject.name == "RRSIG" ||
                 testObject.name == "NSEC" ||
                 testObject.name == "NSEC3" ||
                 testObject.name == "DNSKEY" ||
                 testObject.name == "DNAME" ||
                 testObject.name == "DS") &&
                testObject.status != DNSSECTest.GOOD) {
                maxGrade = Math.max(2, maxGrade);
            }

            // If they fail EDNS0, then it's a D
            if (testObject.name == "EDNS0" && testObject.status != DNSSECTest.GOOD) {
                maxGrade = Math.max(3, maxGrade);
            }
        }
        if (!finished)
            hostInfo[hostName]['grades'].grade = "?"
        else
            hostInfo[hostName]['grades'].grade = grades[maxGrade]
    }
}

function makeLight(creator, type, name, host) {
    var result = creator.createObject(resultGrid)
    result.name = name
    result.test = testManager.makeTest(type, host, name);
    hostInfo[host]['tests'].push(result)
    //hosttests[host].push(result.test)
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
    hostInfo[host] = {}
    hostInfo[host]['grades'] = hostGrade
    hostInfo[host]['tests'] = []
    hostInfo[host]['hostnum'] = hosts.length - 1

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
    makeLight(resultComponent, 10, "DNAME", host)

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
    if (currentSingleTestHost == "") {
        resetTests()
        currentTestHostNum = 0;
    }
    waitText.waitLength = 1;
    currentTestNumber = -1;
    restartCount = 0;
    dnssecCheckTop.state = "running"
    testManager.inTestLoop = true;
    setTestStartMessage();
    giveUpTimer.start()
    countingTimer.start()
    runNextTest();
}

function runNextTest() {

    // See if we're just hanging around to finish testing
    if (!testManager.inTestLoop) {
        if (testManager.outStandingRequests() > 0) {
            testManager.startQueuedTransactions();
            testManager.checkAvailableUpdates();
            testManager.dataAvailable();
            timer.start();
        } else {
            stopTesting();
        }

        return;
    }

    // still processing tests
    currentTestNumber++

    // check to see if we're beyond the maximum test for the current host
    if (currentTestNumber >= hostInfo[hosts[currentTestHostNum]]['tests'].length) {
        // done with this host
        currentTestNumber = 0
        currentTestHostNum++
        if (currentSingleTestHost != "" || currentTestHostNum >= hosts.length) {
            // done entirely
            testManager.inTestLoop = false;
            timer.start() // we'll return at least once more to check outstanding
            return
        }
    }

    hostInfo[hosts[currentTestHostNum]]['tests'][currentTestNumber].test.check()
    timer.start()
    setTestStartMessage()
}

function stopTesting() {
    timer.stop()
    giveUpTimer.stop()
    countingTimer.stop()
    testManager.inTestLoop = false;
    testManager.checkAvailableUpdates();
    if (currentSingleTestHost === "" || haveAllTestsRun())
        dnssecCheckTop.state = "ran"
    else
        dnssecCheckTop.state = "half"
    testStatusMessage.text = ""
    testResultMessage.text = "All tests have completed; Click on a bubble for details"
    currentSingleTestHost = ""
    assignHostGrade();
}

function restartRunningTests() {
    testManager.cancelOutstandingRequests()
    for(var i = 0 ; i < hosts.length; i++) {
        var hostName = hosts[i]

        for(var j = 0; j < hostInfo[hostName]['tests'].length; j++) {
            var testObject = hostInfo[hostName]['tests'][j].test
            if (testObject.status === DNSSECTest.TESTINGNOW || testObject.status === DNSSECTest.UNKNOWN) {
                testObject.status = DNSSECTest.UNKNOWN
                testObject.check()
            }
        }
    }
}

function cancelTests() {
    for(var i = 0 ; i < hosts.length; i++) {
        var hostName = hosts[i]

        for(var j = 0; j < hostInfo[hostName]['tests'].length; j++) {
            var testObject = hostInfo[hostName]['tests'][j].test
            if (testObject.status == DNSSECTest.TESTINGNOW || testObject.status == DNSSECTest.UNKNOWN)
                testObject.status = DNSSECTest.BAD
        }
    }

    stopTesting()
}

function giveUpTimerHook() {
    // if we get here, we're fairly sunk as it's taken a long time for the requests to complete.
    // So we retry or give up.
    if (restartCount >= giveUpTimer.retryCount) {
        giveUpMessage.state = "visible"
        cancelTests()
    } else {
        restartRunningTests()
        restartCount++
    }
}

function setTestStartMessage() {
    if (currentTestHostNum >= 0 && currentTestHostNum < hosts.length &&
        currentTestNumber > -1 &&
        currentTestNumber <= hostInfo[hosts[currentTestHostNum]]['tests'].length) {

        testStatusMessage.text =
                "Test Status: sending test for " +
                hostInfo[hosts[currentTestHostNum]]['tests'][currentTestNumber].test.name +
                " to " + hosts[currentTestHostNum]
    } else {
        testStatusMessage.text = "Idle"
    }
}

function resetTests() {
    for(var i = 0 ; i < hosts.length; i++) {
        var hostName = hosts[i]

        for(var j = 0; j < hostInfo[hostName]['tests'].length; j++) {
            hostInfo[hostName]['tests'][j].test.status = DNSSECTest.UNKNOWN
        }

        hostInfo[hostName]['grades'].grade = "?"
    }

    dnssecCheckTop.state = ""
}

function submitResults() {
    var datalist = [];
    var count = 0;
    for(var i = 0 ; i < hosts.length; i++) {
        var hostName = hosts[i]
        datalist.push("server" + i)
        datalist.push(testManager.sha1hex(hostName))
        for(var j = 0; j < hostInfo[hostName]['tests'].length; j++) {
            var testObject = hostInfo[hostName]['tests'][j].test
            datalist.push(testObject.name + i)
            datalist.push(testObject.status)
        }
        count++;
    }
    testManager.submitResults(datalist)
}
