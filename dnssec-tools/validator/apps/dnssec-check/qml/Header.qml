// import QtQuick 1.0 // to target S60 5th Edition or Maemo 5
import QtQuick 1.1

Item {
    width: resultGrid.resultWidth
    height: headerLabel.height

    property alias text: headerLabel.text

    Text {
        id: headerLabel
        font.pixelSize: 14
        font.underline: true
        anchors.centerIn: parent

        color: "white"
        text: ""
    }
}
