#ifndef DATASUBMITTER_H
#define DATASUBMITTER_H

#include <QObject>

class DataSubmitter : public QObject
{
    Q_OBJECT
public:
    explicit DataSubmitter(QObject *parent = 0);

    void submitResults(QString locationDescription);
signals:

public slots:
    void responseReceived(QNetworkReply *response);

};

#endif // DATASUBMITTER_H
