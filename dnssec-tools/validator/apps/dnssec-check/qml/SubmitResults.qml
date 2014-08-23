import QtQuick 2.0

Item {
    id: rootResults
    z: 1

    property alias text: messageBox.text
    property string submittingText: ""


    InfoBox {
        id: messageBox
        state: "hidden"
        anchors.fill: parent
    }

    state: "hidden"

    states: [
        State {
            name: "hidden"
            PropertyChanges {
                target: rootResults
                submittingText: ""
                opacity: 0
                visible: false
            }
            PropertyChanges {
                target: messageBox
                state:  "hidden"
            }
        },
        State {
            name: "waiting"
            PropertyChanges {
                target: rootResults
                submittingText: "Sending results to the results server..."
                opacity: 0
                visible: true
            }
            PropertyChanges {
                target: messageBox
                state:  "hidden"
            }
        },
        State {
            name: "visible"
            PropertyChanges {
                target: rootResults
                submittingText: ""
                opacity: 1
            }
            PropertyChanges {
                target: messageBox
                state:  "visible"
            }
        }
    ]
}
