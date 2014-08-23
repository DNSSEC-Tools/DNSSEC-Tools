import QtQuick 2.0

InfoBox {
    id: resultInfo
    state: "hidden"

    anchors.fill: parent
    width: dnssecCheckTop.width
    height: dnssecCheckTop.height

    widthPercent: .75

    property string testName: ""
    property string testResult: ""
    property string resolverName: ""

    text: ""

    onTestNameChanged: { updateText() ; }
    onTestResultChanged: { updateText(); }
    onResolverNameChanged: { updateText(); }

    function updateText() {
        resultInfo.text = "<style>a { color: #8888ff; } a:visited { color: red; }</style><h2>DNSSEC-Check Result</h2>" +
                "<p>Test Name: <b>" + resultInfo.testName +
                "</b></p><p>Tested resolver: <b>" + resolverName +
                "</b></p><p>Test Result: <b>" + testResult + "</b></p>"
    }

    Component.onCompleted: {
        updateText()
    }
}
