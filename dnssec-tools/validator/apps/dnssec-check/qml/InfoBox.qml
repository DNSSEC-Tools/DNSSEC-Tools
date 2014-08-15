import QtQuick 2.0

Flickable {
    id: infoBox
    z: 1

    property string statusText: ""
    property alias text: messageText.text
    property double widthPercent: .75
    state: "hidden"

    signal dismissed

    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

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

        height: (parent.height < messageBox.height ? parent.height - bottomScrollBox.height * 2 : messageBox.height)
        width: widthPercent * parent.width

        contentWidth: messageBox.width
        contentHeight: messageBox.height

        Rectangle {
            id: messageBox
            color: "black"
            anchors.centerIn: parent
            z: parent.z + 2
            width: messageText.width + border.width * 2 + 10
            height: messageText.height + infoButtonBox.height + anchors.margins * 16
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
                font.pixelSize: 14
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
        height: downArrow.height + border.width*2
        anchors.margins: 0
        opacity: infoFlickable.atYEnd ? 0 : 1
        Image {
            id: downArrow
            source: "qrc:/images/arrow.png"
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
        height: upArrow.height + border.width*2
        anchors.margins: 0
        opacity: infoFlickable.atYBeginning ? 0 : 1
        Image {
            id: upArrow
            source: "qrc:/images/arrow.png"
            anchors.centerIn: parent
            rotation: 180
        }

        MouseArea {
            anchors.fill: parent
            onClicked: {
                infoFlickable.contentY -= infoFlickable.height / 2
            }
        }
    }

    Image {
        id: quitBox
        anchors.top: topScrollBox.bottom
        anchors.right: topScrollBox.right
        anchors.topMargin: 0
        anchors.rightMargin: 4
        z: infoFlickable.z + 2

        source: "qrc:/images/xbox.png"

        MouseArea {
            anchors.fill: parent
            // make the mouse area thrice as big as the parent for finger-friendliness
            anchors.margins: -parent.width;
            onClicked: {
                infoBox.state = "hidden"
                dismissed()
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
            PropertyChanges {
                target: infoBox
                visible: false
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
            PropertyChanges {
                target: infoBox
                visible: true
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
