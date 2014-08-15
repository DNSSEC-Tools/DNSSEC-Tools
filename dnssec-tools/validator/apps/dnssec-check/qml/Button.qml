import QtQuick 2.0

Rectangle {
    id: root
    color: "#aac"
    border.color: "#bbe"
    z: 100

    property int maxDefaultButtonSize: 125

    width: (buttonText.width + 10 > maxDefaultButtonSize) ? (buttonText.width + 10) : maxDefaultButtonSize
    height: buttonText.height + 6
    border.width: 2
    radius: 5
    anchors.margins: 5

    property alias text: buttonText.text
    property bool enabled: true

    signal clicked

    Text {
        id: buttonText
        font.pixelSize: 16
        anchors.centerIn: parent
        color: root.enabled ? "black" : "gray"
    }
    MouseArea {
        anchors.fill: parent
        onClicked:    { if (enabled) { root.clicked() } }
    }
}
