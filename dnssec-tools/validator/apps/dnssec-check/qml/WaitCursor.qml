import QtQuick 1.0

Item {
    id: waitCursor
    z: 50
    width: waitTextContent.width + waitBackground.border.width * 4
    height: waitTextContent.height + waitBackground.border.width * 4
    opacity:  1

    property string waitText: "<p>Runing Tests<p>Please Wait"

    Rectangle {
        id: waitBackground
        border.color: "#fff"
        border.width: 10
        radius: 5
        color: "#444"
        opacity: .25
        anchors.fill: parent
        z: parent.z + 1
    }

    Text {
        id: waitTextContent
        text: waitText
        color: "#fff"
        z: parent.z + 2
        font.pixelSize: 60
        anchors.centerIn: parent
        horizontalAlignment: Text.AlignHCenter
        opacity: .75
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
                opacity: .75
            }
            when: dnssecCheckTop.state == "running"
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
