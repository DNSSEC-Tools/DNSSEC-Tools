import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 360
    id: dnssecCheckTop
    color: "black"

    property string dnssecToolsVersion: "1.11"

    Timer {
        id:       timer;
        interval: 5;
        running:  false;
        repeat:   true;
        onTriggered: { DNSSECCheck.runNextTest(); }
    }

    Rectangle {
        id: titleBox
        width: parent.width - anchors.margins * 2
        height: titleText.height + readyText.height + 4
        color: "#444"
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.margins: 10
        radius: 2
        Text {
            id: titleText
            text: "DNSSEC-Check"
            color: "white"
            font.pixelSize: 20
            font.underline: true
            font.bold: true
            anchors.top: parent.top
            anchors.horizontalCenter: parent.horizontalCenter
        }
        Text {
            id: readyText
            text: "Is your world ready?"
            color: "white"
            font.pixelSize: 12
            font.italic: true
            anchors.top: titleText.bottom
            anchors.horizontalCenter: parent.horizontalCenter
        }

        Text {
            id: titleHelpButton
            text: "Help"
            color: "white"
            anchors.verticalCenter: parent.verticalCenter
            anchors.right: parent.right
            anchors.rightMargin: 10
            horizontalAlignment: Text.AlignRight
            MouseArea {
                anchors.fill: parent
                onClicked: {
                    helpBox.state = "visible"
                }
            }
        }
    }

    Rectangle {
        id: resultsBox
        anchors.top: titleBox.bottom
        anchors.left: titleBox.left
        width:  titleBox.width
        height: resultGrid.height + 2 * border.width + 8
        color: "black"
        border.color: resultGrid.children.length > 0 ? "#bbbbbb" : "black"
        border.width: 1
        anchors.topMargin: 10

        Grid {
            id: resultGrid
            columns: getColumns()
            spacing: 5
            x: parent.border.width * 2 + 4
            y: parent.border.width * 2 + 4

            property int resultWidth: 54

            Header { text: "Host" ; width: 150 }
            Header { text: "DNS" }
            Header { text: "TCP" }
            Header { text: "DO" }
            Header { text: "AD" }
            Header { text: "RRSIG" }
            Header { text: "EDNS0" }
            Header { text: "NSEC" }
            Header { text: "NSEC3" }
            Header { text: "DNSKEY" }
            Header { text: "DS" }
        }
    }


    NewServerBox {
        id: newServerBox
        anchors.top: resultsBox.bottom
        anchors.left: resultsBox.left
        onAddHost: {
            DNSSECCheck.addSingleHost(hostaddr)
        }
    }

    Row {
        id: buttonRow
        anchors.top: newServerBox.bottom
        anchors.horizontalCenter: newServerBox.horizontalCenter
        anchors.topMargin: 10

        spacing: 10

        Button {
            id: testButton
            text: "Run Tests"
            onClicked: {
                DNSSECCheck.runAllTests()
            }
            enabled: resultGrid.rows > 0
        }

        Button {
            id: resetButton
            text: "Reset"
            enabled: false
            onClicked: {
                DNSSECCheck.resetTests()
            }
        }

        Button {
            id: submitButton
            text: "Submit Results"
            onClicked: {
                dnssecCheckTop.state = "wantsToSubmit"
            }
            enabled: false
        }

        // moved to the top...
        /*
        Button {
            id: helpButton
            text: "Help"
            onClicked: {
                helpBox.state = "visible"
            }
        }
        */

        Button {
            id: resolverButton
            text: "Resolvers"
            onClicked: {
                resolverMenu.state = "visible"
            }
        }

        Button {
            id: quitButton
            text: "Quit"
            enabled: resultsReceivedBox.state == "waiting" ? false : true;
            onClicked: {
                Qt.quit()
            }
        }
    }



    Text {
        id: testResultMessage
        anchors.top: buttonRow.bottom
        anchors.leftMargin: 10
        anchors.topMargin:  4
        anchors.left: parent.left
        font.pointSize:  12
        text: ""
        onLinkActivated: Qt.openUrlExternally(link)
        color: "white"
        wrapMode: Text.Wrap
        width: parent.width - anchors.margins * 2
    }
    Text {
        id: testStatusMessage
        anchors.top: testResultMessage.bottom
        anchors.left: parent.left
        anchors.leftMargin: 10
        anchors.topMargin:  2
        font.pointSize:  12
        text: ""
        onLinkActivated: Qt.openUrlExternally(link)
        color: "white"
        wrapMode: Text.Wrap
        width: parent.width - anchors.margins * 2
    }

    property string runningStatus: "idle"
    Text {
        id: statusMessage
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.margins: 10
        font.pointSize: 12
        font.italic: true
        text: ((resultsReceivedBox.submittingText != "" || parent.runningStatus != "") ? "Status: " : "") +
              ((parent.runningStatus == "idle" && resultsReceivedBox.submittingText != "") ? "" : parent.runningStatus) +
              ((resultsReceivedBox.submittingText != "" && parent.runningStatus != "idle") ? ", " : "") +
              resultsReceivedBox.submittingText
        color: "white"
    }
    Text {
        id: dtlink
        anchors.bottom: parent.bottom
        anchors.margins: 10
        anchors.right: parent.right
        font.pointSize:  12
        text: "<style>a { color: #8888ff; } a:visited { color: red; }</style><a href=\"http://www.dnssec-tools.org/\">http://www.dnssec-tools.org/</a>"
        onLinkActivated: Qt.openUrlExternally(link)
    }

    WantToSubmitInfo {
        id: wantToSubmitBox
        anchors.fill: parent
        width: dnssecCheckTop.width
        height: dnssecCheckTop.height
        opacity: 0

        onSubmitOk: {
            DNSSECCheck.submitResults()
            resultsReceivedBox.state = "waiting"
        }
    }

    SubmitResults {
        id: resultsReceivedBox

        anchors.fill: parent
        width: dnssecCheckTop.width
        height: dnssecCheckTop.height

        text: testManager.submissionMessage

        Connections {
            target: testManager
            onSubmissionMessageChanged: {
                resultsReceivedBox.state = "visible"
            }
        }
    }

    Help { id: helpBox }

    HostMenu {
        id: hostMenu
        onRemoveHost: {
            DNSSECCheck.removeHost(host)
        }
        onTestHost: {
            DNSSECCheck.testHost(host)
        }
        onClearHost: {
            DNSSECCheck.clearHost(host)
        }
    }

    ResolverMenu {
        id: resolverMenu
        onClearResolvers: {
            DNSSECCheck.clearServers()
        }
        onLoadSystemResolvers: {
            DNSSECCheck.clearServers()
            DNSSECCheck.loadInitial()
        }
    }

    InfoBox {
        id: startupMessage
        state: testManager.getSetting("initMessageDisplayed") == dnssecToolsVersion ? "hidden" : "visible"

        anchors.fill: parent
        width: dnssecCheckTop.width
        height: dnssecCheckTop.height

        widthPercent: .75

        text: "<style>a { color: #8888ff; } a:visited { color: red; }</style><h2>Welcome to DNSSEC-Check</h2><img style=\"float: right;\" src=\"qrc:/images/dnssec-check-64x64.png\" />
        <p>On the following screen you will see a list of the DNS resolvers configured for your system.</p>
        <p>Click on the <b>'Run Tests'</b> button
        to run some DNSSEC compliance tests on them.  After all the tests have run, please consider clicking the <b>'Submit Results'</b>
        button to help measure the world-wide DNSSEC deployment.
	<p>For more information on DNSSEC-Check, please visit <a
        href=\"https://www.dnssec-tools.org/wiki/index.php/DNSSEC-Check\">the DNSSEC-Check
        wiki page</a></p>"

        onDismissed: {
            testManager.saveSetting("initMessageDisplayed", dnssecToolsVersion)
        }
    }

    WaitCursor {
        id: waitText
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter:   newServerBox.verticalCenter
    }

    ResultInfo {
        id: resultInfo
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
    }

    Connections {
        target: testManager
        onLastResultMessageChanged: {
            testResultMessage.text = "Test Result: " + testManager.lastResultMessage
        }
    }

    state: ""
    states: [
        State {
            name: ""
            PropertyChanges {
                target: resetButton
                enabled: false
            }
            PropertyChanges {
                target: resolverButton
                enabled: true
            }
        },
        State {
            name: "cleared"
            PropertyChanges {
                target:  resetButton
                enabled: false
            }
            PropertyChanges {
                target:  testButton
                enabled: false
            }
            PropertyChanges {
                target:  submitButton
                enabled: false
            }
            PropertyChanges {
                target:  resolverButton
                enabled: true
            }
        },
        State {
            name: "half"
            PropertyChanges {
                target: resetButton
                enabled: true
            }
        },

        State {
            name: "running"
            PropertyChanges {
                target: submitButton
                enabled: false
            }
            PropertyChanges {
                target: resolverButton
                enabled: false
            }
            PropertyChanges {
                target: testButton
                enabled: false
            }
            PropertyChanges {
                target: resetButton
                enabled: false
            }
            PropertyChanges {
                target: dnssecCheckTop
                runningStatus: "Running all tests"
            }

        },
        State {
            name: "ran"
            PropertyChanges {
                target: submitButton
                enabled: resultGrid.rows > 0
            }
            PropertyChanges {
                target: testButton
                enabled: true
            }
            PropertyChanges {
                target: resetButton
                enabled: true
            }
            PropertyChanges {
                target: dnssecCheckTop
                runningStatus: "idle"
            }
        },
        State {
            name: "submitted"
            PropertyChanges {
                target: submitButton
                enabled: false
            }
            PropertyChanges {
                target: testButton
                enabled: true
            }
            PropertyChanges {
                target: resetButton
                enabled: true
            }
        },
        State {
            name: "wantsToSubmit"
            PropertyChanges {
                target: submitButton
                enabled: false
            }
            PropertyChanges {
                target: testButton
                enabled: true
            }
            PropertyChanges {
                target: resetButton
                enabled: true
            }
            PropertyChanges {
                target: wantToSubmitBox
                opacity: 1
            }
        }
    ]

    transitions: [
        Transition {
            from: "*"
            to: "*"
            PropertyAnimation {
                properties: "opacity,font.color"
                duration:   250
            }
        }
    ]
}
