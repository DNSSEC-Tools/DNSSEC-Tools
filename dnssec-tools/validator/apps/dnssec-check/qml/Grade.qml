import QtQuick 1.0

Item {

    width: resultGrid.resultWidth
    height: rectBorder.height
    property alias grade: hostGrade.text

    Rectangle {
        id: rectBorder
        width: 16
        height: 16
        anchors.centerIn: parent


        color: "black"
        border.color: "#bbb"
        border.width: 0

        Text {
            id: hostGrade
            anchors.centerIn: parent
            font.pixelSize:   parent.height - parent.border.width * 3
            text: "?"
            color: "white"
        }
    }
}
