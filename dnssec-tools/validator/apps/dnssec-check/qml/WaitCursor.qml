import QtQuick 2.0

Item {
    id: waitCursor
    z: 50
    width: dnssecCheckTop.width
    height: newServerBox.height
    opacity: 0
    visible: false

    property int waitLength:    0
    property int waitLengthMax: giveUpTimer.interval * (giveUpTimer.retryCount + 1)/ 1000;

    Rectangle {
        id: rect
        width: 50;
        height: 10;
        anchors.verticalCenter: parent.verticalCenter
        color: Qt.lighter("green");
        border.color: Qt.darker("green")
        border.width: 2
        x: 0
        z: parent.z + 2
    }

    Rectangle {
        id: rectFilling
        width: parent.width * waitLength / waitLengthMax;
        height: parent.height
        anchors.top: waitCursor.top
        anchors.left: waitCursor.left
        color: Qt.lighter("blue")
        border.color: Qt.darker("blue")
        border.width: 2
        z: parent.z + 1
    }

    Text {
        id: testingText
        text: "Testing..."
        color: "white"
        font.italic: true
        font.pixelSize: parent.height * 3 / 4
        anchors.centerIn: parent
        z: parent.z + 3
    }

    states: [
        State {
            name: ""
            PropertyChanges {
                target: waitCursor
                opacity: 0
                visible: false
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: waitCursor
                opacity: 1
                visible: true
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
