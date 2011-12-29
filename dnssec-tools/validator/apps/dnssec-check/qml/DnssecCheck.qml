import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 400
    id: root

    Rectangle {
        anchors.top: parent.top
        anchors.right: parent.right
        width:  7*parent.width/8
        height: resultGrid.height + 2 * border.width
        color: "white"
        border.color: "#bbbbbb"
        border.width: 1

        Grid {
            id: resultGrid
            columns: 2
            spacing: 5
            x: parent.border.width * 2
            y: parent.border.width * 2
        }
    }

    Text {
        text: "hello world";
        font.pixelSize: 20

        MouseArea {
            anchors.fill: parent
            onClicked: {
                DNSSECCheck.runAllTests()
            }
        }
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
        console.log("testing: " + TestManager.can_get_ds)
    }
}
