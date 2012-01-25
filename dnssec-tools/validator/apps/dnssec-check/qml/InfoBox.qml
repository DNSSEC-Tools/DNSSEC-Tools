import QtQuick 1.0

Item {
    id: infoBox
    z: 1

    property string statusText: ""
    property alias text: messageText.text
    property double widthPercent: .5
    state: "hidden"

    Rectangle {
        color: "white"
        opacity: .75
        anchors.fill: parent
        z: parent.z + 1
        MouseArea {
            anchors.fill: parent
            onClicked: { } // no op to prevent it from passing lower
        }
    }
    Rectangle {
        id: messageBox
        color: "black"
        anchors.centerIn: parent
        z: parent.z + 2
        height: messageText.height + infoButtonBox.height + anchors.margins * 5
        width: widthPercent * parent.width
        border.color: submitOk.border.color
        border.width: 5
        radius: 5
        anchors.margins: 10
        Text {
            id: messageText
            anchors.top: messageBox.top
            anchors.left: messageBox.left
            width: parent.width - anchors.margins*2
            color: "white"
            anchors.margins: 10
            font.pointSize: 12
            wrapMode: Text.Wrap

            text: ""
            onLinkActivated: Qt.openUrlExternally(link)
        }
        Row {
            id: infoButtonBox
            anchors.top: messageText.bottom
            //activeFocus: anchors.left: messageText.left
            anchors.margins: 10
            spacing: 10
            anchors.horizontalCenter: messageText.horizontalCenter

            Button {
                id: submitOk
                text: "Ok"
                onClicked: {
                    infoBox.state = "hidden"
                    dnssecCheckTop.state = "submitted"
                }
            }
        }
    }

    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: infoBox
                opacity: 0
            }
            PropertyChanges {
                target: infoBox
                statusText: ""
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: infoBox
                opacity: 1
            }
            PropertyChanges {
                target: infoBox
                statusText: ""
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
