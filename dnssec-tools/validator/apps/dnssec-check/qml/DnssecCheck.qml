import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width: 800
    height: 400
    id: root

    Rectangle {
        id: titleBox
        width: 7*parent.width/8
        height: titleText.height + 4
        color: "#cccccc"
        anchors.top: parent.top
        anchors.right: parent.right
        Text {
            id: titleText
            text: "Tests"
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
        color: "white"
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

    Rectangle {
        id: testButton
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.leftMargin: border.width
        anchors.topMargin: border.width
        color: "#ccccff"
        border.color: "blue"
        border.width: 5
        radius: 10
        width: buttonText.width + 2 * border.width
        height: buttonText.height + 2 * border.width

        Text {
            id: buttonText
            text: "test";
            font.pixelSize: 20
            anchors.centerIn: parent

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    DNSSECCheck.runAllTests()
                }
            }
        }
    }

    Rectangle {
        width:  resultsBox.width
        height: newHost.height + border.width
        border.color: "black"
        border.width: 1
        anchors.top: resultsBox.bottom
        anchors.left: resultsBox.left
        anchors.topMargin: 10

        TextInput {
            id: newHost
            anchors.left: parent.left
            anchors.leftMargin: 5
            width: parent.width
            font.pixelSize: buttonText.font.pixelSize

            property string defaultText: "add new resolver address"

            text: defaultText

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    console.log("foo" + newHost.text)
                    if (newHost.text == newHost.defaultText) {
                        console.log("bar")
                        newHost.text = ""
                    }
                    newHost.focus = true
                }
            }

            onAccepted: {
                DNSSECCheck.addSingleHost(newHost.text)
                newHost.text = newHost.defaultText
                newHost.focus = false
            }

            states:[
                State {
                    when: newHost.text == newHost.defaultText
                    PropertyChanges {
                        target: newHost
                        font.italic: true
                        color: "#bbb"
                    }
                }

            ]
        }
    }

    Component.onCompleted: {
        DNSSECCheck.loadInitial()
    }
}
