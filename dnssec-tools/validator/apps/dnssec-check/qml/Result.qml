import QtQuick 2.0
import DNSSECTools 1.0

Rectangle {
    id: result

    property int size: 16
    //property alias name: testName.text
    property string name: ""
    property DNSSECTest test

    width:  resultGrid.resultWidth
    height: size
    radius: size/2
    border.color: Qt.darker(color)
    border.width: 2
    //color: "#bbbbbb"
    //state: "unknown"
    color:   "black"

    MouseArea {
        anchors.fill: parent
        Timer {
            id: runTimer
            interval: 200
            running: false; repeat: false
            onTriggered: { running = false ; test.check() ;  stop()}
        }

        onClicked: {
            if (test.status == DNSSECTest.UNKNOWN) {
                // run immediately; we have no status yet
                test.check()
            } else {
                resultInfo.testName = test.name
                resultInfo.testResult = test.message
                resultInfo.resolverName = test.serverAddress
                resultInfo.state = "visible"
            }
            dnssecCheckTop.state = "half"
        }
        hoverEnabled: true
        onEntered: { // testName.font.pixelSize = parent.size/3 ; testName.color = "white"
            testResultMessage.text = "Test Result: " + name + " on " + test.serverAddress + ": " + test.message}
        onExited:  { // testName.font.pixelSize = parent.size/4 ; testName.color = "black"
                     testResultMessage.text = "" }
    }

    states: [
        State {
            name: "unknown"
            when: test.status == DNSSECTest.UNKNOWN
            PropertyChanges {
                target: result
                color: "#bbbbbb"
            }
        },
        State {
            name: "good"
            when: test.status == DNSSECTest.GOOD
            PropertyChanges {
                target: result
                color: "#bbffbb"
            }
        },
        State {
            name: "bad"
            when: test.status == DNSSECTest.BAD
            PropertyChanges {
                target: result
                color: "#ffbbbb"
            }
        },
        State {
            name: "warning"
            when: test.status == DNSSECTest.WARNING
            PropertyChanges {
                target: result
                color: "orange"
            }
        },
        State {
            name: "testing"
            when: test.status == DNSSECTest.TESTINGNOW
            PropertyChanges {
                target: result
                color: "#bbbbff"
            }
        }
    ]

    transitions: [
        Transition {
            from: "*"
            to: "*"
            ColorAnimation { duration: 250 }
        }
    ]
}
