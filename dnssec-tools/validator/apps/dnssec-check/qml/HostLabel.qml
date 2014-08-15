import QtQuick 2.0

Rectangle {
    width:  label.width
    height: label.height
    color:  "black"

    property alias hostName: label.text

    Text {
        id: label
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        font.pixelSize: 14
        font.bold: true
        color: "white"
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            hostMenu.host = hostName
            hostMenu.state = "visible"
        }

        hoverEnabled: true
        onEntered: { testStatusMessage.text = "<i>(click on a resolver to test/reset/remove it)<li>" }
        onExited:  { testStatusMessage.text = "" }
    }
}
