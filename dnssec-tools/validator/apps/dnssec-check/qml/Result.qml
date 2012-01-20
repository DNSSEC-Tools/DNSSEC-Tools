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
        onClicked: {
            console.log("starting test")
            test.check()
            console.log("result string: " + test.serverAddress + " -> " + test.status + " should be " + DNSSECTest.GOOD)
            if (test.status == DNSSECTest.GOOD) {
                console.log("setting state to good")
                //result.state = "good"
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
