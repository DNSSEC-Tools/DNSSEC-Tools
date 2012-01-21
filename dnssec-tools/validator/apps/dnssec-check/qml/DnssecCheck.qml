import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 400
    id: root
    color: "black"

    Timer {
        id:       timer;
        interval: 5;
        running:  false;
        repeat:   true;
        onTriggered: { DNSSECCheck.runNextTest(); }
    }

    Rectangle {
        id: titleBox
        width: parent.width
        height: titleText.height + 4
        color: "#444"
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.margins: 10
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


    NewServerBox {
        id: newServerBox
        anchors.top: resultsBox.bottom
        anchors.left: resultsBox.left
        onAddHost: {
            DNSSECCheck.addSingleHost(hostaddr)
        }
    }

    Row {
        anchors.top: newServerBox.bottom
        anchors.left: newServerBox.left
        anchors.topMargin: 10

        spacing: 10

        Button {
            id: testButton
            text: "Run Tests"
            onClicked: {
                DNSSECCheck.runAllTests()
            }
        }

        Button {
            id: resetButton
            text: "Reset"
            onClicked: {
                DNSSECCheck.resetTests()
            }
        }

        Button {
            id: quitButton
            text: "Quit"
            onClicked: {
                Qt.quit()
            }
        }

        Button {
            id: submitButton
            text: "Submit"
            onClicked: {
                DNSSECCheck.submitResults()
            }
        }
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
    }
}
