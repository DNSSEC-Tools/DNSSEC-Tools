#ifndef PCAPWATCHER_H
#define PCAPWATCHER_H

#include <sys/time.h>
#include <stdint.h>
#include <pcap.h>

#include <QThread>
#include <QTimer>
#include <QSignalMapper>
#include <QMenu>

#include "DNSData.h"

#include "qtauto_properties.h"

//
// Implemantation note:
//   This switches back and forth between the pcap loop and the Qt loop, switching
//   ever 100ms to give both event loops time to do things

class PcapWatcher : public QThread
{
    Q_OBJECT
public:
    explicit PcapWatcher(QObject *parent = 0);

    void     setupDeviceMenu(QMenu *menu);

signals:
    void     failedToOpenDevice(QString errMsg);
    void     failedToOpenFile(QString errMsg);
    void     addNode(QString nodeName);
    void     addNodeData(QString nodeName, DNSData data, QString logMessage);

public slots:
    void     openDevice();
    void     openFile(const QString &fileNameToOpen = "", bool animatePlayback = false);
    void     closeDevice();
    void     processPackets();
    
private:
    void run();

    QSignalMapper       m_mapper;

    QString             m_filterString;
    struct bpf_program  m_filterCompiled;
    pcap_t             *m_pcapHandle;
    char                m_errorBuffer[PCAP_ERRBUF_SIZE];

    QTimer              m_timer;

    QTAUTO_GET_SET_SIGNAL(QString, fileName);
    QTAUTO_GET_SET_SIGNAL(QString, deviceName);
    QTAUTO_GET_SET_SIGNAL(bool, animatePlayback);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(QString fileName READ fileName WRITE setFileName NOTIFY fileNameChanged) public: const QString &fileName() const { return m_fileName; } signals: void fileNameChanged(); void fileNameChanged(QString); public slots: void setFileName(const QString &newval) { if (newval != m_fileName) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(fileName) << " " << m_fileName << " => " << newval); m_fileName = newval; emit fileNameChanged(); emit fileNameChanged(newval); } } private: QString m_fileName;
    /* AGST */ Q_PROPERTY(QString deviceName READ deviceName WRITE setDeviceName NOTIFY deviceNameChanged) public: const QString &deviceName() const { return m_deviceName; } signals: void deviceNameChanged(); void deviceNameChanged(QString); public slots: void setDeviceName(const QString &newval) { if (newval != m_deviceName) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(deviceName) << " " << m_deviceName << " => " << newval); m_deviceName = newval; emit deviceNameChanged(); emit deviceNameChanged(newval); } } private: QString m_deviceName;
    /* AGST */ Q_PROPERTY(bool animatePlayback READ animatePlayback WRITE setAnimatePlayback NOTIFY animatePlaybackChanged) public: const bool &animatePlayback() const { return m_animatePlayback; } signals: void animatePlaybackChanged(); void animatePlaybackChanged(bool); public slots: void setAnimatePlayback(const bool &newval) { if (newval != m_animatePlayback) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(animatePlayback) << " " << m_animatePlayback << " => " << newval); m_animatePlayback = newval; emit animatePlaybackChanged(); emit animatePlaybackChanged(newval); } } private: bool m_animatePlayback;
};

#endif // PCAPWATCHER_H
