#ifndef PCAPWATCHER_H
#define PCAPWATCHER_H

#include <pcap.h>

#include <QThread>

class PcapWatcher : public QThread
{
    Q_OBJECT
public:
    explicit PcapWatcher(QObject *parent = 0);
    QString  deviceName();
    void     setDeviceName(const QString &deviceName);


signals:
    void     failedToOpenDevice(QString errMsg);
    void     addNode(QString nodeName);
    
public slots:
    void     openDevice();
    void     closeDevice();
    
private:
    void run();

    QString             m_filterString;
    struct bpf_program  m_filterCompiled;
    QString             m_deviceName;
    pcap_t             *m_pcapHandle;
    char                m_errorBuffer[PCAP_ERRBUF_SIZE];
};

#endif // PCAPWATCHER_H
