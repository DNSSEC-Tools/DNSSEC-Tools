import QtQuick 1.0

Item {
    id: rootResults
    z: 1

    Rectangle {
        color: "white"
        opacity: .75
        anchors.fill: parent
        z: parent.z + 1 -5
    }
    Rectangle {
        id: submitBox
        color: "black"
        anchors.centerIn: parent
        z: parent.z + 2
        height: submitDescription.height + submitButtonBox.height + anchors.margins * 5
        width: parent.width / 2
        border.color: submitOk.border.color
        border.width: 5
        radius: 5
        anchors.margins: 10
        Text {
            id: submitDescription
            anchors.top: submitBox.top
            anchors.left: submitBox.left
            width: parent.width - anchors.margins
            color: "white"
            anchors.margins: 10
            font.pointSize: 12
            wrapMode: Text.Wrap

            text: testManager.submissionMessage
        }
        Row {
            id: submitButtonBox
            anchors.top: submitDescription.bottom
            //activeFocus: anchors.left: submitDescription.left
            anchors.margins: 10
            spacing: 10
            anchors.horizontalCenter: submitDescription.horizontalCenter

            Button {
                id: submitOk
                text: "Ok"
                onClicked: {
                    rootResults.state = "hidden"
                    dnssecCheckTop.state = "submitted"
                }
            }
        }
    }

    state: "hidden"

    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: rootResults
                opacity: 0
            }
        },

        State {
            name: "visible"
            PropertyChanges {
                target: rootResults
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
