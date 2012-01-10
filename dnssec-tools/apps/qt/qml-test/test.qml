import QtQuick 1.0
import QtWebKit 1.0

Rectangle {
  width: 800
  height: 800

  Rectangle {
    id: loadrect
    width: loading.width + 10
    height: loading.height + 10
    z: 10
    anchors.centerIn: parent
    color: "white"
    opacity: .5

    Text {
      id: loading
      text: "loading..."
      font.pixelSize: 40
      anchors.centerIn: parent
      color: "black"
      z: 11
    }
  }
  WebView {
    url:  "http://www.dnssec-deployment.org/"
    anchors.fill: parent
    onLoadFinished: { loadrect.opacity = 0 }
  }
}
