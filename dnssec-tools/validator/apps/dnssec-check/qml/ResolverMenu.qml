import QtQuick 2.0

Flickable {
    id: resolverMenuBox
    z: 1

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    state: "hidden"

    signal dismissed
    signal clearResolvers
    signal loadSystemResolvers

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
                id: clearResolvers
                text: "Clear Resolver List"
                width: 300
                onClicked: {
                    resolverMenuBox.clearResolvers()
                    resolverMenuBox.state = "hidden"
                }
            }
            Button {
                id: loadSystemResolvers
                text: "Load System Resolvers"
                width: 300
                onClicked: {
                    resolverMenuBox.loadSystemResolvers()
                    resolverMenuBox.state = "hidden"
                }
            }
            Button {
                id: cancelResolvers
                text: "Cancel"
                width: 300
                onClicked: {
                    resolverMenuBox.state = "hidden"
                }
            }
        }
    }

    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: resolverMenuBox
                opacity: 0
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: resolverMenuBox
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
