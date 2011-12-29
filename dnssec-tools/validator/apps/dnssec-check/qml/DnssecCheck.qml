import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 400
    id: root
    color: "black"

    Rectangle {
        id: titleBox
        width: 7*parent.width/8
        height: titleText.height + 4
        color: "#444"
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.rightMargin: 10
        anchors.topMargin: 5
        radius: 2
        Text {
            id: titleText
            text: "DNSSEC-Check"
            color: "white"
            font.pixelSize: 20
            font.underline: true
            font.bold: true
            anchors.centerIn: parent
        }
    }

    Rectangle {
        id: resultsBox
        anchors.top: titleBox.bottom
        anchors.left: titleBox.left
        width:  titleBox.width
        height: resultGrid.height + 2 * border.width
        color: "black"
        border.color: "#bbbbbb"
        border.width: 1
        anchors.topMargin: 10

        Grid {
            id: resultGrid
            columns: 2
            spacing: 5
            x: parent.border.width * 2
            y: parent.border.width * 2
        }
    }

    Button {
        id: testButton
        anchors.top: parent.top
        anchors.left: parent.left

        onClicked: {
            DNSSECCheck.runAllTests()
        }
    }

    NewServerBox {
        id: newServerBox
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
    }
}
