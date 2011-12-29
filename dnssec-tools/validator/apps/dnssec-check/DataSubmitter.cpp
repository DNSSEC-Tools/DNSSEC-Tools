#include "DataSubmitter.h"

DataSubmitter::DataSubmitter(QObject *parent) :
    QObject(parent)
{
}

void DataSubmitter::submitResults(QString locationDescription)
{
    QUrl accessURL = resultServerBaseURL;
    accessURL.addQueryItem("dataVersion", "1");
    int count=0;
    foreach(QString serverAddress, m_serverAddresses) {
        accessURL.addQueryItem("server" + QString::number(count++), serverAddress);
    }

    foreach(QStatusLight *light, m_tests) {
        accessURL.addQueryItem(light->name() + QString::number(light->rowNumber()), light->statusString());
    }

    accessURL.addQueryItem("locationDescription", locationDescription);
    accessURL.addQueryItem("DNSSECToolsVersion", "1.11");

    if (!m_manager) {
        m_manager = new QNetworkAccessManager();
        connect(m_manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(respnonseReceived(QNetworkReply*)));
    }
    m_manager->get(QNetworkRequest(accessURL));
}

void DataSubmitter::respnonseReceived(QNetworkReply *response)
{
    QMessageBox msg;
    if (response->error() == QNetworkReply::NoError)
        msg.setText("We've successfully recevied your test results.  Thank you for your help!");
    else
        msg.setText("Unfortunately we failed to send your test results to the collection server.");
    msg.exec();
}

