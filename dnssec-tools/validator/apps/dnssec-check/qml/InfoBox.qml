import QtQuick 1.0

Flickable {
    id: infoBox
    z: 1

    property string statusText: ""
    property alias text: messageText.text
    property double widthPercent: .5
    state: "hidden"

    signal dismissed

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
    Flickable {
        id: infoFlickable
        z: parent.z + 3
        anchors.centerIn: parent
        anchors.margins: 10
        flickableDirection: Flickable.VerticalFlick
        clip: true

        height: (parent.height < messageBox.height ? parent.height - bottomScrollBox.height * 4 : messageBox.height)
        width: widthPercent * parent.width

        contentWidth: messageBox.width
        contentHeight: messageBox.height

        Rectangle {
            id: messageBox
            color: "black"
            anchors.centerIn: parent
            z: parent.z + 2
            width: messageText.width + border.width * 2 + 10
            height: messageText.height + infoButtonBox.height + anchors.margins * 5
            border.color: submitOk.border.color
            border.width: 5
            radius: 5
            anchors.margins: 10
            Text {
                id: messageText
                anchors.top: messageBox.top
                anchors.left: messageBox.left
                width: infoBox.width * infoBox.widthPercent - infoFlickable.anchors.margins * 2 - messageBox.anchors.margins * 2 -
                       messageBox.border.width * 2
                color: "white"
                anchors.margins: 10
                font.pointSize: 10
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
                        dismissed()
                    }
                }
            }
        }
    }
    Rectangle {
        id: bottomScrollBox
        color: "#333"
        anchors.topMargin: -border.width
        anchors.top: infoFlickable.bottom
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.horizontalCenterOffset: -15
        border.color: submitOk.border.color
        border.width: 5
        z: infoFlickable.z - 1
        width: messageBox.width
        height: downDots.height + border.width*2
        anchors.margins: 0
        opacity: infoFlickable.atYEnd ? 0 : 1
        Text {
            id: downDots
            text: "..."
            color: "white"
            font.pointSize: 12
            anchors.centerIn: parent
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                infoFlickable.contentY += infoFlickable.height / 2
            }
        }
    }

    Rectangle {
        id: topScrollBox
        color: "#333"
        anchors.bottomMargin: -border.width
        anchors.bottom: infoFlickable.top
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.horizontalCenterOffset: -15
        border.color: submitOk.border.color
        border.width: 5
        z: infoFlickable.z - 1
        width: messageBox.width
        height: downDots.height + border.width*2
        anchors.margins: 0
        opacity: infoFlickable.atYBeginning ? 0 : 1
        Text {
            id: upDots
            text: "..."
            color: "white"
            font.pointSize: 12
            anchors.centerIn: parent
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                infoFlickable.contentY -= infoFlickable.height / 2
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
