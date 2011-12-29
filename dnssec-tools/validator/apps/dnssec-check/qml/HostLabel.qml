import QtQuick 1.0

Rectangle {
    width: label.width
    height: label.height

    property alias hostName: label.text

    Text {
        id: label
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        font.pixelSize: 20
    }
}
