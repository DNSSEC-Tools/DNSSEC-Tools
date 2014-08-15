// import QtQuick 2.0 // to target S60 5th Edition or Maemo 5
import QtQuick 1.1

Item {
    width: resultGrid.resultWidth
    height: headerLabel.height + 2

    property alias text: headerLabel.text

    Text {
        id: headerLabel
        font.pixelSize: 12
        font.bold: true
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top

        color: "white"
        text: ""
    }

    Rectangle {
        id: headerUnderline
        width: parent.width
        height: 2
        color: "white"
        anchors.bottom: parent.bottom
        anchors.horizontalCenter: parent.horizontalCenter
    }
}
