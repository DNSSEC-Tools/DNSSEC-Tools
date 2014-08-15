import QtQuick 2.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    id: newHostBar
    width:  titleBox.width - (addButton.opacity == 0 ? 0 : addButton.width + addButton.border.width * 8)
    height: newHost.height + border.width*4
    border.color: "#c0c0c0"
    border.width: 1
    anchors.top: resultsBox.bottom
    anchors.left: resultsBox.left
    anchors.topMargin: 10
    color: "#222"
    opacity: dnssecCheckTop.state != "running"

    signal addHost(string hostaddr)

    TextInput {
        id: newHost
        anchors.left: parent.left
        anchors.leftMargin: 5
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width - addButton.width
        color: "white"
        font.pixelSize: 20

        property string defaultText: "Click to add a new resolver address"

        text: defaultText

        MouseArea {
            anchors.fill: parent
            onClicked: {
                if (newHost.text == newHost.defaultText) {
                    newHost.text = ""
                }
                newHost.focus = true
            }
        }

        onAccepted: {
            acceptHost()
        }

        function acceptHost() {
            if (newHost.text != "") {
                addHost(newHost.text)
            }
            newHost.text = newHost.defaultText
            newHost.closeSoftwareInputPanel()
            newHost.focus = false
            dnssecCheckTop.state = (dnssecCheckTop.state == "ran") ? "half" : ""
        }

        states:[
            State {
                when: newHost.text == newHost.defaultText
                PropertyChanges {
                    target: newHost
                    font.italic: true
                    color: "#999"
                }
            }

        ]
    }

    Button {
        id: addButton
        text: "Add"
        onClicked: {
            newHost.acceptHost()
        }
        anchors.verticalCenter: parent.verticalCenter
        anchors.left: parent.right
        anchors.top: newHost.top
        anchors.margins: 5
        enabled: (newHost.text == newHost.defaultText || newHost.text == "") ? false : true
        opacity: (newHost.text == newHost.defaultText || newHost.text == "") ? 0 : 1.0
    }
}
