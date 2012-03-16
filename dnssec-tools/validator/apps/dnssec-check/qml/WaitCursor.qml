import QtQuick 1.0

Item {
    id: waitCursor
    z: 50
    width: dnssecCheckTop.width
    height: newServerBox.height
    opacity: 0

    Rectangle {
        id: rect
        width: 50;
        height: 10;
        anchors.verticalCenter: parent.verticalCenter
        color: Qt.lighter("green");
        border.color: Qt.darker("green")
        border.width: 2
        x: 0
    }

    Text {
        id: testingText
        text: "Testing..."
        color: "white"
        font.italic: true
        font.pixelSize: parent.height * 3 / 4
        anchors.centerIn: parent
    }

    states: [
        State {
            name: ""
            PropertyChanges {
                target: waitCursor
                opacity: 0
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: waitCursor
                opacity: 1
            }
            when: dnssecCheckTop.state == "running"
        }

    ]

    transitions: [
        Transition {
            from: ""
            to: "visible"
            PropertyAnimation {
                properties: "opacity"
                duration:   100
            }
            SequentialAnimation {
                //running: state == "visible"
                loops: Animation.Infinite
                PropertyAnimation {
                    target: rect
                    from: 0
                    to: waitCursor.width - rect.width
                    property: "x"
                    easing.type: Easing.InOutSine
                    duration: 500
                }
                PropertyAnimation {
                    target: rect
                    to: 0
                    from: waitCursor.width - rect.width
                    property: "x"
                    easing.type: Easing.InOutSine
                    duration: 500
                }
            }
        }
    ]
}
