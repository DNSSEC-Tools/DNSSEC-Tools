import QtQuick 1.0

Rectangle {
    id: root
    color: "#aac"
    border.color: "#bbe"
    width: (buttonText.width + 10 > 150) ? (buttonText.width + 10) : 150
    height: buttonText.height + 10
    border.width: 2
    radius: 5
    anchors.margins: 5

    property alias text: buttonText.text
    property bool enabled: true

    signal clicked

    Text {
        id: buttonText
        font.pixelSize: 20
        anchors.centerIn: parent
        color: root.enabled ? "black" : "gray"
    }
    MouseArea {
        anchors.fill: parent
        onClicked:    {root.clicked()}
    }
}
