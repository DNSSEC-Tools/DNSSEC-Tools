import QtQuick 1.0

Item {
    id: rootWant
    z: 1

    signal submitOk

    Rectangle {
        color: "white"
        opacity: .75
        anchors.fill: parent
        z: parent.z + 1

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
