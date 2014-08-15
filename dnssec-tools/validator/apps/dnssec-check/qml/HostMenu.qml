import QtQuick 2.0

Flickable {
    id: hostMenuBox
    z: 1

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    property string host: ""

    state: "hidden"

    signal dismissed
    signal removeHost(string host)
    signal clearHost(string host)
    signal testHost(string host)

    MouseArea {
        anchors.fill: parent
        onClicked: { } // no op to prevent it from passing lower
        hoverEnabled: true
        onEntered: { }
        onExited:  { }
    }

    Rectangle {
        color: "white"
        opacity: .75
        anchors.fill: parent
        z: parent.z + 1
    }

    Rectangle {
        color: "black"
        anchors.centerIn: parent
        height: column.height + 20
        width: column.width + 20
        opacity: 1
        z: parent.z + 2

        Column {
            id: column
            spacing: 10
            anchors.centerIn: parent
            Button {
                id: removeHost
                text: "Remove " + host
                width: 300
                onClicked: {
                    hostMenuBox.removeHost(host)
                    hostMenuBox.state = "hidden"
                }
            }
            Button {
                id: resetHost
                text: "Reset " + host
                width: 300
                onClicked: {
                    hostMenuBox.clearHost(host)
                    hostMenuBox.state = "hidden"
                }
            }
            Button {
                id: testHost
                text: "Test " + host
                width: 300
                onClicked: {
                    hostMenuBox.testHost(host)
                    hostMenuBox.state = "hidden"
                }
            }
            Button {
                id: cancelHost
                text: "Cancel"
                width: 300
                onClicked: {
                    hostMenuBox.state = "hidden"
                }
            }
        }
    }

    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: hostMenuBox
                opacity: 0
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: hostMenuBox
                opacity: 1
            }
        }

    ]

    transitions: [
        Transition {
            from: "*"
            to: "*"
            PropertyAnimation {
                properties: "opacity"
                duration:   250
            }
        }
    ]
}
