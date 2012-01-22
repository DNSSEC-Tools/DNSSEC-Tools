import QtQuick 1.0
import DNSSECTools 1.0

Rectangle {
    id: result

    property int size: 40
    property alias name: testName.text
    property DNSSECTest test

    width:  size
    height: size
    radius: size/2
    border.color: Qt.darker(color)
    border.width: 2
    //color: "#bbbbbb"
    //state: "unknown"
    color:   "black"

    Text {
        id: testName
        font.pixelSize: parent.size/4
        anchors.centerIn: parent
        z: 3
    }
    Text {
        id: testNameBackGround
        font.pixelSize: testName.font.pixelSize
        anchors.centerIn: parent
        color: "white"
        z: 2
    }
    MouseArea {
        anchors.fill: parent
        Timer {
            id: runTimer
            interval: 200
            running: false; repeat: false
            onTriggered: { running = false ; test.check() ; stop()}
        }

        onClicked: {
            if (test.status == DNSSECTest.UNKNOWN) {
                // run immediately; we have no status yet
                test.check()
            } else {
                test.status = DNSSECTest.UNKNOWN // need a timer to break before the test
                runTimer.start()
                // test.check()
            }
        }
        hoverEnabled: true
        onEntered: { testName.font.pixelSize = parent.size/3 ; testName.color = "white" }
        onExited:  { testName.font.pixelSize = parent.size/4 ; testName.color = "black"  }
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
