import QtQuick 2.0

Item {
    id: rootWant
    z: 1

    signal submitOk
    property double widthPercent: .75
    state: "hidden"

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
        id: submitFlickable

        z: parent.z + 3
        anchors.centerIn: parent
        anchors.margins: 10
        flickableDirection: Flickable.VerticalFlick
        clip: true

        height: (parent.height < submitBox.height ? parent.height - bottomScrollBox.height * 4 : submitBox.height)
        width: widthPercent * parent.width

        contentWidth: submitBox.width
        contentHeight: submitBox.height

    Rectangle {
        id: submitBox
        color: "black"
        anchors.centerIn: parent
        z: parent.z + 5
        height: submitDescription.height + submitButtonBox.height + anchors.margins * 5
        width: submitDescription.width + border.width * 2 + 10
        border.color: submitOk.border.color
        border.width: 5
        radius: 5
        anchors.margins: 10
        Text {
            id: submitDescription
            anchors.top: submitBox.top
            anchors.left: submitBox.left
            width: rootWant.width * rootWant.widthPercent - submitFlickable.anchors.margins * 2 - submitBox.anchors.margins * 2 -
                   submitBox.border.width * 2
            color: "white"
            anchors.margins: 10
            font.pixelSize: 16
            wrapMode: Text.Wrap

            text: "<p>First, thanks for offering to submit your data!

            <p>The data you submit will contain the following:
            <ul>
            <li>A SHA1 hashed IP address for each resolver.</li>
            <li>The results of each test sent to the resolver</li>
            </ul>

            If this is ok to submit, please click the 'Submit It' button below."
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
                text: "Submit It"
                onClicked: {
                    rootWant.submitOk()
                    dnssecCheckTop.state = "submitted"
                }
            }
            Button {
                id: submitCancel
                text: "Cancel"
                onClicked: {
                    dnssecCheckTop.state = "ran"
                }
            }
        }
    }
    }
    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: rootWant
                opacity: 0
                visible: false
            }
            PropertyChanges {
                target: rootWant
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: rootWant
                opacity: 1
                visible: true
            }
            PropertyChanges {
                target: rootWant
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
