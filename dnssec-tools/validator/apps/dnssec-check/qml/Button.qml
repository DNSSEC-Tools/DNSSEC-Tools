import QtQuick 1.0

Rectangle {
    id: root
    color: "#ccccff"
    border.color: "white"
    width: buttonText.width + 10
    height: buttonText.height + 10
    border.width: 2
    radius: 5
    anchors.margins: 5

    signal clicked

    Text {
        id: buttonText
        text: "test";
        font.pixelSize: 20
        anchors.centerIn: parent

        MouseArea {
            anchors.fill: parent
            onClicked:    {root.clicked()}
        }
    }
}
