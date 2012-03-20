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
        border.color: "white"
        border.width: 0

        Text {
            id: hostGrade
            anchors.centerIn: parent
            font.pixelSize:   parent.height - parent.border.width * 3
            text: "?"
            color: {
                if (text == "?")
                    return "#bbb"
                if (text == "A")
                    return Qt.lighter("green")
                if (text == "B")
                    return "orange"
                if (text == "C" || text == "D")
                    return "yellow"
                if (text == "F")
                    return "red"
            }
        }
    }
}
