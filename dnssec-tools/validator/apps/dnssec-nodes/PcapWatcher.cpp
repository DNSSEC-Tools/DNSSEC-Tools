#include "PcapWatcher.h"

PcapWatcher::PcapWatcher(QObject *parent) :
    QObject(parent), m_filterString("port 53"), m_deviceName(""), m_pcapHandle(0)
{
}

QString PcapWatcher::deviceName()
{
    return m_deviceName;
}

void PcapWatcher::setDeviceName(const QString &deviceName)
{
    m_deviceName = deviceName;
}

void PcapWatcher::openDevice()
{
    bpf_u_int32 mask, net;

    if (pcap_lookupnet(m_deviceName.toAscii().data(), &net, &mask, m_errorBuffer)) {
        emit failedToOpenDevice(tr("could not get netmask for device: %s").arg(m_deviceName));
        return;
    }

    m_pcapHandle = pcap_open_live(m_deviceName.toAscii().data(), BUFSIZ, 1, 1000, m_errorBuffer);
    if (!m_pcapHandle) {
        // TODO: do something on error
        emit failedToOpenDevice(QString(m_errorBuffer));
        return;
    }

    if (m_filterString.length() > 0) {
        if (pcap_compile(m_pcapHandle, &m_filterCompiled, m_filterString.toAscii().data(), 1, mask) < -1) {
            emit failedToOpenDevice(tr("failed to parse the filter: %s").arg(pcap_geterr(m_pcapHandle)));
            return;
        }
    }

    if (pcap_setfilter(m_pcapHandle, &m_filterCompiled) < -1) {
        emit failedToOpenDevice(tr("failed to install the filter: %s").arg(pcap_geterr(m_pcapHandle)));
        return;
    }
}
