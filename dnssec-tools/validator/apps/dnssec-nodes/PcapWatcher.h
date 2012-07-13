#ifndef PCAPWATCHER_H
#define PCAPWATCHER_H

#include <pcap.h>

#include <QThread>
#include <QTimer>
#include <QSignalMapper>
#include <QMenu>

#include "DNSData.h"

//
// Implemantation note:
//   This switches back and forth between the pcap loop and the Qt loop, switching
//   ever 100ms to give both event loops time to do things

class PcapWatcher : public QThread
{
    Q_OBJECT
public:
    explicit PcapWatcher(QObject *parent = 0);
    QString  deviceName();

    void     setupDeviceMenu(QMenu *menu);

signals:
    void     failedToOpenDevice(QString errMsg);
    void     addNode(QString nodeName);
    void     addNodeData(QString nodeName, DNSData data);

public slots:
    void     setDeviceName(const QString &deviceName);
    void     openDevice();
    void     closeDevice();
    void     processPackets();
    
private:
    void run();

    QSignalMapper       m_mapper;

    QString             m_filterString;
    struct bpf_program  m_filterCompiled;
    QString             m_deviceName;
    pcap_t             *m_pcapHandle;
    char                m_errorBuffer[PCAP_ERRBUF_SIZE];

    QTimer              m_timer;

    int                 counter;
};

#endif // PCAPWATCHER_H
