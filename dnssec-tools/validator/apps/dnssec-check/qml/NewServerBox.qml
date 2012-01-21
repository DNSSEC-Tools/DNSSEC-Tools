import QtQuick 1.0
import "DNSSECCheck.js" as DNSSECCheck
import DNSSECTools 1.0

Rectangle {
    width:  resultsBox.width
    height: newHost.height + border.width
    border.color: "black"
    border.width: 1
    anchors.top: resultsBox.bottom
    anchors.left: resultsBox.left
    anchors.topMargin: 10
    color: "#222"

    signal addHost(string hostaddr)

    TextInput {
        id: newHost
        anchors.left: parent.left
        anchors.leftMargin: 5
        width: parent.width
        color: "white"
        font.pixelSize: 20

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
            if (newHost.text != "") {
                addHost(newHost.text)
            }
            newHost.text = newHost.defaultText
            newHost.closeSoftwareInputPanel()
            newHost.focus = false
            dnssecCheckTop.state = ""
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
}
