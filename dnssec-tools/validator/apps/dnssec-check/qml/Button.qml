import QtQuick 1.0

Rectangle {
    id: root
    color: "#aac"
    border.color: "#bbe"
    width: buttonText.width + 10
    height: buttonText.height + 10
    border.width: 2
    radius: 5
    anchors.margins: 5

    property alias text: buttonText.text

    signal clicked

    Text {
        id: buttonText
        font.pixelSize: 20
        anchors.centerIn: parent

        MouseArea {
            anchors.fill: parent
            onClicked:    {root.clicked()}
        }
    }
}
