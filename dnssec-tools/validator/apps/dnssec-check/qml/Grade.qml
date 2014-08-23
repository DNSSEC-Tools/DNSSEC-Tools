import QtQuick 2.0

Item {

    width: resultGrid.resultWidth
    height: rectBorder.height
    property alias grade: hostGrade.text
    property alias gradeScore: hostScore.text

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
        Text {
            id: hostScore
            anchors.centerIn: parent
            font.pixelSize:   parent.height - parent.border.width * 3
            text: "?"
            opacity: 0
            color: "white"
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                if (hostGrade.opacity == 1.0) {
                    hostGrade.opacity = 0.0;
                    hostScore.opacity = 1.0;
                } else {
                    hostGrade.opacity = 1.0;
                    hostScore.opacity = 0.0;
                }
            }
        }
    }
}
