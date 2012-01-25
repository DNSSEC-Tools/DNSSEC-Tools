import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 400
    id: dnssecCheckTop
    color: "black"

    Timer {
        id:       timer;
        interval: 5;
        running:  false;
        repeat:   true;
        onTriggered: { DNSSECCheck.runNextTest(); }
    }

    Rectangle {
        id: titleBox
        width: parent.width
        height: titleText.height + 4
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
            anchors.centerIn: parent
        }
    }

    Rectangle {
        id: resultsBox
        anchors.top: titleBox.bottom
        anchors.left: titleBox.left
        width:  titleBox.width
        height: resultGrid.height + 2 * border.width
        color: "black"
        border.color: "#bbbbbb"
        border.width: 1
        anchors.topMargin: 10

        Grid {
            id: resultGrid
            columns: 2
            spacing: 5
            x: parent.border.width * 2
            y: parent.border.width * 2
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
        anchors.left: newServerBox.left
        anchors.topMargin: 10

        spacing: 10

        Button {
            id: testButton
            text: "Run Tests"
            onClicked: {
                DNSSECCheck.runAllTests()
            }
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

        Button {
            id: helpButton
            text: "Help"
            onClicked: {
                helpBox.state = "visible"
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

    property string runningStatus: "idle"
    Text {
        anchors.top: buttonRow.bottom
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
        anchors.top: buttonRow.bottom
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

    InfoBox {
        id: startupMessage
        state: testManager.getSetting("initMessageDisplayed") ? "hidden" : "visible"

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
            testManager.saveSetting("initMessageDisplayed", true)
        }
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
    }

    state: ""
    states: [
        State {
            name: ""
            PropertyChanges {
                target: resetButton
                enabled: false
            }
        },

        State {
            name: "running"
            PropertyChanges {
                target: submitButton
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
                enabled: true
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
